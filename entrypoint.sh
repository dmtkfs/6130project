#!/bin/bash
set -e

# Ensure the log directories exist
mkdir -p /var/log/ids_app
mkdir -p /var/log/supervisor

# Adjust ownership and permissions
chown -R ids_user:adm /var/log/ids_app /var/log/supervisor
chmod -R 750 /var/log/ids_app /var/log/supervisor

# Execute the main process
exec "$@"
