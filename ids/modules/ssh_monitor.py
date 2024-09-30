# ids/modules/ssh_monitor.py

import time
import re
import os
import logging
from collections import defaultdict
import getpass  # To capture user details


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        # Log file path for host and container
        self.host_log_file_path = os.getenv("HOST_LOG_FILE_PATH", "/var/log/auth.log")
        self.container_log_file_path = os.getenv(
            "CONTAINER_LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )
        self.failed_attempts = defaultdict(int)
        logging.info(
            f"SSHMonitor initialized with host log file path: {self.host_log_file_path}"
        )
        logging.info(
            f"SSHMonitor initialized with container log file path: {self.container_log_file_path}"
        )

    def start(self):
        """
        Start monitoring SSH logs for failed and successful login attempts.
        """
        try:
            self.monitor_log_file(self.host_log_file_path, "Host")
            self.monitor_log_file(self.container_log_file_path, "Container")
        except Exception as e:
            logging.error(f"Error in SSHMonitor: {e}")

    def monitor_log_file(self, log_file_path, source):
        """
        Monitor the provided log file for SSH events.
        """
        if not os.path.exists(log_file_path):
            logging.error(f"SSH auth log not found at {log_file_path} ({source})")
            return

        with open(log_file_path, "r") as file:
            file.seek(0, os.SEEK_END)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(1)
                    continue
                self.process_line(line, source)

    def process_line(self, line, source):
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
                f"{timestamp} - User: {current_user} - Failed SSH login attempt from {ip_address} "
                f"({source}): Attempt {self.failed_attempts[ip_address]}"
            )
            logging.warning(message)
            for alert in self.alerts:
                alert.send_alert(f"Failed SSH Login Attempt ({source})", message)

        elif successful_login_pattern.search(line):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: {current_user} - Successful SSH login detected ({source}): {line.strip()}"
            logging.info(message)
            for alert in self.alerts:
                alert.send_alert(f"Successful SSH Login ({source})", message)
