#!/bin/sh
set -e

# Ensure the log directories exist
# Create directory for the log file if it doesn't exist
# Adjust ownership and permissions
if [ -n "$LOG_FILE_PATH" ]; then
    mkdir -p $(dirname $LOG_FILE_PATH)
    chown -R ids_user:ids_group $(dirname $LOG_FILE_PATH)
fi

chown -R root:root /var/log/supervisor

# Set the password for ids_user if provided
if [ -n "$IDS_USER_PASSWORD" ]; then
    echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd
fi

# Generate SSH host keys
ssh-keygen -A

# Start Supervisord
exec /usr/bin/supervisord -c /etc/supervisord.conf
