#!/bin/sh
set -e

# Ensure the log directory and files are accessible
mkdir -p /var/log/ids_app

# Setup ids.log with correct ownership and permissions
if [ ! -f /var/log/ids_app/ids.log ]; then
    touch /var/log/ids_app/ids.log
    chown root:ids_group /var/log/ids_app/ids.log
    chmod 0640 /var/log/ids_app/ids.log
fi

# Ensure blacklist.txt exists with appropriate permissions
if [ ! -f /var/log/ids_app/blacklist.txt ]; then
    touch /var/log/ids_app/blacklist.txt
    chown root:ids_group /var/log/ids_app/blacklist.txt
    chmod 664 /var/log/ids_app/blacklist.txt
fi

# Set permissions for the mounted directory
chown root:ids_group /var/log/ids_app
chmod 0750 /var/log/ids_app

# Set the password for ids_user if provided
if [ -n "$IDS_USER_PASSWORD" ]; then
    echo "ids_user:${IDS_USER_PASSWORD}" | chpasswd
fi

# Generate SSH host keys if not present
ssh-keygen -A

# Limit ICMP (ping) requests to 1 per second per IP (with burst of 5 pings)
iptables -A INPUT -p icmp --icmp-type echo-request -i eth0 -m limit --limit 1/s --limit-burst 5 -j LOG --log-prefix "ICMP Flood: "

# Start rsyslog to capture iptables logs
rsyslogd

# Start Supervisord
exec /usr/bin/supervisord -c /etc/supervisord.conf
