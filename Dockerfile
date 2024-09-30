# Use Alpine as the base image
FROM alpine:latest

# Install necessary tools and dependencies
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

# Declare a build argument for the password
ARG IDS_USER_PASSWORD

# Create a non-root user and group with fixed UID and GID
RUN addgroup -g 1000 adm && \
    adduser -S ids_user -G adm -u 1000 && \
    echo "ids_user:$IDS_USER_PASSWORD" | chpasswd && \
    chsh -s /bin/sh ids_user && \
    echo 'export PS1="docker_container:\\w\\$ "' >> /home/ids_user/.profile

# Set the working directory
WORKDIR /ids_app

# Copy the application files
COPY ids/ /ids_app/ids/
COPY supervisord.conf /etc/supervisord.conf

# Copy the entrypoint script and make it executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create directories for logs and change ownership to ids_user
RUN mkdir -p /var/log/supervisor /var/log/ids_app /var/run/sshd && \
    chown -R ids_user:adm /var/log/ids_app /var/log/supervisor

# Install and configure SSH
RUN echo 'root:Docker!' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    ssh-keygen -A && \
    echo "export VISIBLE=now" >> /etc/profile

# Run as root to allow Supervisor to drop privileges as needed
USER root

# Expose the SSH port
EXPOSE 22222

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Start Supervisor and SSHD
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]
