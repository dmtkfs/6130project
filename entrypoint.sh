#!/bin/sh
set -e

# Ensure the log directories exist
mkdir -p /var/log/ids_app
mkdir -p /var/log/supervisor

# Adjust ownership and permissions
chown -R ids_user:ids_group /var/log/ids_app
chown -R root:root /var/log/supervisor

# Generate SSH host keys
ssh-keygen -A

# Start Supervisord
exec supervisord -c /etc/supervisord.conf
