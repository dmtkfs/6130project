#!/bin/sh
set -e

# Ensure the necessary directories exist
mkdir -p /var/run/sshd

# Ensure the log directory and files are accessible
mkdir -p /var/log/ids_app
if [ ! -f /var/log/ids_app/ids.log ]; then
    touch /var/log/ids_app/ids.log
fi
if [ ! -f /var/log/ids_app/blacklist.txt ]; then
    touch /var/log/ids_app/blacklist.txt
fi

# Set permissions for the mounted directory and files
# chown -R 1001:ids_group /var/log/ids_app
# chmod -R 775 /var/log/ids_app

# Set the password for ids_user if provided
if [ -n "$IDS_USER_PASSWORD" ]; then
    echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd
fi

# Generate SSH host keys if not present
ssh-keygen -A

# Limit ICMP (ping) requests to 1 per second per IP (with burst of 5 pings)
iptables -A INPUT -p icmp --icmp-type echo-request -i eth0 -m limit --limit 1/s --limit-burst 5 -j ACCEPT

# Start Supervisord
exec /usr/bin/supervisord -c /etc/supervisord.conf
