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

# Set permissions for the main script
RUN chmod +x /ids_app/ids/main.py

# Set the command to run Supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
