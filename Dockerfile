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

# Declaring a build argument for the password
ARG IDS_USER_PASSWORD

# Create a non-root user and group, and set a valid shell
RUN adduser -S ids_user -G adm || true && \
    echo "ids_user:$IDS_USER_PASSWORD" | chpasswd && \
    chsh -s /bin/sh ids_user && \
<<<<<<< HEAD
    echo 'source /etc/profile && export PS1="docker_container@$AZURE_PUBLIC_IP:\\w\\$ "' >> /home/ids_user/.profile

=======
    echo 'export PS1="docker_container@${AZURE_PUBLIC_IP}:\\w\\$ "' >> /home/ids_user/.profile
>>>>>>> c7eb5e1fee5601fae7ba433d58275792c0dabbb4

# Set the working directory
WORKDIR /ids_app

# Copy the entire application
COPY ids/ /ids_app/ids/
COPY supervisord.conf /etc/supervisord.conf

# Create the Supervisor log directory
RUN mkdir -p /var/log/supervisor

# Create the directory for IDS logs
RUN mkdir -p /var/log/ids_app

# Install and configure SSH
RUN mkdir /var/run/sshd && \
    echo 'root:Docker!' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    ssh-keygen -A && \
    echo "export VISIBLE=now" >> /etc/profile

# Set permissions for the main script
RUN chmod +x /ids_app/ids/main.py

# Expose SSH port
EXPOSE 22222

# Start Supervisor and SSHD
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]