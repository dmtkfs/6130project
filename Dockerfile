# Use Alpine as the base image
FROM alpine:latest

# Install Python, pip, Supervisor, and required Python packages
RUN apk update && \
    apk add --no-cache \
    python3 \
    py3-pip \
    supervisor \
    procps \
    coreutils \
    py3-psutil \
    py3-watchdog \
    openssh \
    shadow

# Create a non-root user and group
RUN addgroup -S adm || true && \
    adduser -S ids_user -G adm || true

# Set the working directory
WORKDIR /ids_app

# Copy the entire application
COPY ids/ /ids_app/ids/
COPY supervisord.conf /etc/supervisord.conf

# Create the Supervisor log directory
RUN mkdir -p /var/log/supervisor

# Install and configure SSH
RUN mkdir /var/run/sshd && \\
    echo 'root:Docker!' | chpasswd && \\
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \\
    ssh-keygen -A && \\
    echo "export VISIBLE=now" >> /etc/profile

# Set permissions for the main script
RUN chmod +x /ids_app/ids/main.py

# Expose SSH port
EXPOSE 22222

# Start Supervisor and SSHD
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"] && /usr/sbin/sshd -D