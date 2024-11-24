# Dockerfile

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
    shadow \
    bash \
    iptables

# Create a group and user for the IDS application
RUN addgroup -g 1001 ids_group && \
    adduser -S ids_user -G ids_group -u 1001 && \
    chsh -s /bin/sh ids_user

# Set working directory
WORKDIR /ids_app

# Copy IDS application code
COPY ids/ /ids_app/ids/

# Copy Supervisord configuration
COPY supervisord.conf /etc/supervisord.conf

# Copy Entrypoint script
COPY entrypoint.sh /entrypoint.sh

# Ensure Entrypoint script is executable
RUN chmod +x /entrypoint.sh

# Setting ownership and permissions for /var/log/ids_app
RUN mkdir -p /var/log/ids_app && \
    chown root:ids_group /var/log/ids_app && \
    chmod 0750 /var/log/ids_app

# Create and set permissions for ids.log
RUN touch /var/log/ids_app/ids.log && \
    chown root:root /var/log/ids_app/ids.log && \
    chmod 0640 /var/log/ids_app/ids.log

# Ensure blacklist.txt is created with appropriate permissions on container start
RUN touch /var/log/ids_app/blacklist.txt && \
    chown root:ids_group /var/log/ids_app/blacklist.txt && \
    chmod 664 /var/log/ids_app/blacklist.txt

# Restrict Python execution to root only
RUN chmod 700 /usr/bin/python3

# Expose SSH port
ARG CONTAINER_SSH_PORT
EXPOSE ${CONTAINER_SSH_PORT}

# Update sshd_config to allow ids_user and set the correct port
RUN sed -i "s/#Port 22/Port ${CONTAINER_SSH_PORT}/" /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config && \
    echo 'AllowUsers ids_user' >> /etc/ssh/sshd_config

# Set user password
ARG IDS_USER_PASSWORD
RUN echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd

# Set Entrypoint
ENTRYPOINT ["/entrypoint.sh"]
