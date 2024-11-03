#!/bin/sh
set -e

# Ensure the log directories exist
if [ -n "$LOG_FILE_PATH" ]; then
    mkdir -p $(dirname $LOG_FILE_PATH)
fi

# Set the password for ids_user if provided
if [ -n "$IDS_USER_PASSWORD" ]; then
    echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd
fi

# Generate SSH host keys if not present
ssh-keygen -A

# Start Supervisord
exec /usr/bin/supervisord -c /etc/supervisord.conf
