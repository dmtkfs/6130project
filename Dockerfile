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
    bash  # Added bash if needed for scripts

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

# Create log directories and set permissions
RUN mkdir -p /var/log/supervisor /var/log/ids_app /var/run/sshd && \
    chown -R root:ids_group /var/log/supervisor /var/log/ids_app && \
    chmod -R 775 /var/log/supervisor /var/log/ids_app

# Create and set permissions for the centralized log file
RUN touch /var/log/ids_app/ids.log && \
    chown root:ids_group /var/log/ids_app/ids.log && \
    chmod 664 /var/log/ids_app/ids.log

# Expose SSH port
EXPOSE 22222

# Update sshd_config to allow ids_user and disable root login
RUN sed -i 's/#Port 22/Port 22222/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'AllowUsers ids_user' >> /etc/ssh/sshd_config

# Set user password (if needed)
ARG IDS_USER_PASSWORD
RUN echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd

# Set Entrypoint
ENTRYPOINT ["/entrypoint.sh"]
