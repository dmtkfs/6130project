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

# Create a non-root user for SSH access
adduser -S ssh_user -G ids_group -u 1001
echo "ssh_user:YourSecurePassword" | chpasswd

# Set up SSH directory for the new user
mkdir -p /home/ssh_user/.ssh
chown -R ssh_user:ids_group /home/ssh_user/.ssh
chmod 700 /home/ssh_user/.ssh

# Start Supervisord
exec supervisord -c /etc/supervisord.conf
