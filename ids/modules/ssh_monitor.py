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
        # Host (Azure server) log path
        self.host_auth_log_path = os.getenv("HOST_LOG_FILE_PATH", "/var/log/auth.log")
        # Container (Docker) log path
        self.container_auth_log_path = os.getenv(
            "CONTAINER_LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )
        self.failed_attempts = defaultdict(int)
        logging.info(
            f"SSHMonitor initialized with host log file path: {self.host_auth_log_path} and container log file path: {self.container_auth_log_path}"
        )

    def start(self):
        """
        Start monitoring SSH logs for failed and successful login attempts.
        """
        try:
            # Check if the log paths exist
            if not os.path.exists(self.host_auth_log_path):
                logging.error(
                    f"Host SSH auth log not found at {self.host_auth_log_path}"
                )
            if not os.path.exists(self.container_auth_log_path):
                logging.error(
                    f"Container SSH auth log not found at {self.container_auth_log_path}"
                )

            # Monitor both the host and container logs
            self.monitor_log(self.host_auth_log_path, "Host")
            self.monitor_log(self.container_auth_log_path, "Container")

        except Exception as e:
            logging.error(f"Error in SSHMonitor: {e}")

    def monitor_log(self, log_path, system_type):
        """
        Monitor a specific log file (either host or container) for SSH events.
        """
        try:
            with open(log_path, "r") as file:
                file.seek(0, os.SEEK_END)
                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    self.process_line(line, system_type)
        except Exception as e:
            logging.error(f"Error monitoring {system_type} log {log_path}: {e}")

    def process_line(self, line, system_type):
        """
        Process each line of the log file and check for failed or successful login attempts.
        """
        failed_login_pattern = re.compile(r"Failed password for .* from (\S+)")
        successful_login_pattern = re.compile(r"Accepted publickey for .* from (\S+)")
        current_user = getpass.getuser()  # Get the current user

        failed_match = failed_login_pattern.search(line)
        if failed_match:
            ip_address = failed_match.group(1)
            self.failed_attempts[ip_address] += 1
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = (
                f"{timestamp} - System: {system_type} - User: {current_user} - Failed SSH login attempt from {ip_address}: "
                f"Attempt {self.failed_attempts[ip_address]}"
            )
            logging.warning(message)
            for alert in self.alerts:
                alert.send_alert(f"Failed SSH Login Attempt on {system_type}", message)

        elif successful_login_pattern.search(line):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - System: {system_type} - User: {current_user} - Successful SSH login detected: {line.strip()}"
            logging.info(message)
            for alert in self.alerts:
                alert.send_alert(f"Successful SSH Login on {system_type}", message)
