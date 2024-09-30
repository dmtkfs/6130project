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
    adduser -S ids_user -G ids_group -u 1000 && \
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
    chown -R root:root /var/log/supervisor && \
    chown -R ids_user:ids_group /var/log/ids_app

# Set Entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# No CMD needed since Entrypoint handles Supervisord
CMD []