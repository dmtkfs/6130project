import time
import re
import os
import logging
from collections import defaultdict
import getpass  # To capture user details


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.host_log_file_path = os.getenv(
            "HOST_LOG_FILE_PATH", "/var/log/auth.log"
        )  # Host log path
        self.container_log_file_path = os.getenv(
            "LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )  # Container log path
        self.failed_attempts = defaultdict(int)
        logging.info(
            f"SSHMonitor initialized with host log: {self.host_log_file_path} and container log: {self.container_log_file_path}"
        )

    def start(self):
        """
        Start monitoring SSH logs for failed and successful login attempts on both host and container.
        """
        try:
            # Monitor both host and container logs
            threading.Thread(
                target=self.monitor_log, args=(self.host_log_file_path, "Host")
            ).start()
            threading.Thread(
                target=self.monitor_log,
                args=(self.container_log_file_path, "Container"),
            ).start()
        except Exception as e:
            logging.error(f"Error in SSHMonitor: {e}")

    def monitor_log(self, log_path, source):
        if not os.path.exists(log_path):
            logging.error(f"{source} SSH log not found at {log_path}")
            return

        with open(log_path, "r") as file:
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
        current_user = getpass.getuser()

        failed_match = failed_login_pattern.search(line)
        if failed_match:
            ip_address = failed_match.group(1)
            self.failed_attempts[ip_address] += 1
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = (
                f"{timestamp} - User: {current_user} - {source} - Failed SSH login attempt from {ip_address}: "
                f"Attempt {self.failed_attempts[ip_address]}"
            )
            logging.warning(message)
            for alert in self.alerts:
                alert.send_alert(f"Failed SSH Login Attempt on {source}", message)

        elif successful_login_pattern.search(line):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: {current_user} - {source} - Successful SSH login detected: {line.strip()}"
            logging.info(message)
            for alert in self.alerts:
                alert.send_alert(f"Successful SSH Login on {source}", message)
