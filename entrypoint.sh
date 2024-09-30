#!/bin/sh
set -e

# Start Supervisord
exec supervisord -c /etc/supervisord.conf

# Ensure the log directories exist
mkdir -p /var/log/ids_app
mkdir -p /var/log/supervisor

# Adjust ownership and permissions
chown -R ids_user:ids_group /var/log/ids_app /var/log/supervisor
chmod -R 750 /var/log/ids_app /var/log/supervisor

# Set the password for ids_user if provided
if [ -n "$IDS_USER_PASSWORD" ]; then
    echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd
fi

# Execute the main process
exec "$@"
