# ids/modules/ssh_monitor.py

import time
import re
import os
import logging
from ids.config import BLOCK_THRESHOLD
from collections import defaultdict

class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.auth_log_path = '/host_var_log/auth.log'
        self.failed_attempts = defaultdict(int)

    def start(self):
        try:
            if not os.path.exists(self.auth_log_path):
                logging.error(f"SSH auth log not found at {self.auth_log_path}")
                return

            with open(self.auth_log_path, 'r') as file:
                file.seek(0, os.SEEK_END)
                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    self.process_line(line)
        except Exception as e:
            logging.error(f"Error in SSHMonitor: {e}")

    def process_line(self, line):
        failed_login_pattern = re.compile(r'Failed password for .* from (\S+)')
        successful_login_pattern = re.compile(r'Accepted password for .* from (\S+)')

        failed_match = failed_login_pattern.search(line)
        if failed_match:
            ip_address = failed_match.group(1)
            self.failed_attempts[ip_address] += 1
            message = f"Failed SSH login attempt from {ip_address}: Attempt {self.failed_attempts[ip_address]}"
            for alert in self.alerts:
                alert.send_alert("Failed SSH Login Attempt", message)
        elif successful_login_pattern.search(line):
            message = f"Successful SSH login detected: {line.strip()}"
            for alert in self.alerts:
                alert.send_alert("Successful SSH Login", message)
