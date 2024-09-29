#!/bin/sh

# Stop and remove the existing container if it exists
docker stop secure_container_refactored 2>/dev/null
docker rm secure_container_refactored 2>/dev/null

# Build the Docker image
docker build --no-cache -t secure_container_refactored .

# Run the Docker container
docker run -d \
    --name secure_container_refactored \
    -v /var/log/auth.log:/host_var_log/auth.log:ro \
    secure_container_refactored
