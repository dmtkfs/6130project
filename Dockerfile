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
    shadow

# Create a group and user for the IDS application
RUN addgroup -g 1000 ids_group && \
    adduser -S ids_user -G ids_group -u 1001 && \
    chsh -s /bin/sh ids_user && \
    echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd

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
    chown -R root:root /var/log/supervisor && \
    chown -R ids_user:ids_group /var/log/ids_app

# Expose SSH port
EXPOSE 22222

# Update sshd_config to allow ids_user and disable root login
RUN sed -i 's/#Port 22/Port 22222/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'AllowUsers ids_user' >> /etc/ssh/sshd_config


# Set Entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# No CMD needed since Entrypoint handles Supervisord
CMD []