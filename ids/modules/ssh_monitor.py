# ids/modules/ssh_monitor.py

import time
import re
import os
import logging
from collections import defaultdict
from ids.config import BLOCK_THRESHOLD
import getpass  # To capture user details


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        # Retrieve the log file path from environment variable or use default
        self.auth_log_path = os.getenv("LOG_FILE_PATH", "/host_var_log/auth.log")
        self.failed_attempts = defaultdict(int)
        logging.info(f"SSHMonitor initialized with log file path: {self.auth_log_path}")

    def start(self):
        """
        Start monitoring SSH logs for failed and successful login attempts.
        """
        try:
            if not os.path.exists(self.auth_log_path):
                logging.error(f"SSH auth log not found at {self.auth_log_path}")
                return

            with open(self.auth_log_path, "r") as file:
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
        """
        Process each line of the log file and check for failed or successful login attempts.
        """
        failed_login_pattern = re.compile(r"Failed password for .* from (\S+)")
        successful_login_pattern = re.compile(r"Accepted password for .* from (\S+)")
        current_user = getpass.getuser()  # Get the current user

        failed_match = failed_login_pattern.search(line)
        if failed_match:
            ip_address = failed_match.group(1)
            self.failed_attempts[ip_address] += 1
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = (
                f"{timestamp} - User: {current_user} - Failed SSH login attempt from {ip_address}: "
                f"Attempt {self.failed_attempts[ip_address]}"
            )
            logging.warning(message)
            for alert in self.alerts:
                alert.send_alert("Failed SSH Login Attempt", message)

        elif successful_login_pattern.search(line):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: {current_user} - Successful SSH login detected: {line.strip()}"
            logging.info(message)
            for alert in self.alerts:
                alert.send_alert("Successful SSH Login", message)
