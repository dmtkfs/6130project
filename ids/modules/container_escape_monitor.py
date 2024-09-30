# ids/modules/container_escape_monitor.py

import logging
import os
import time
import getpass  # To capture user details


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        # Retrieve the log file path from environment variables or use the default path
        self.log_file_path = os.getenv("LOG_FILE_PATH", "/host_var_log/auth.log")
        self.alerts = alerts
        self.suspicious_keywords = [
            "container escape",
            "access denied",
            "unauthorized access",
        ]
        # Capture the user who started the monitoring
        self.current_user = getpass.getuser()
        logging.info(
            f"ContainerEscapeMonitor initialized with log file path: {self.log_file_path} by user: {self.current_user}"
        )

    def start(self):
        logging.info(f"Starting ContainerEscapeMonitor on {self.log_file_path}")
        retries = 0
        max_retries = 5
        while retries < max_retries:
            try:
                with open(self.log_file_path, "r") as log_file:
                    log_file.seek(0, os.SEEK_END)  # Move to the end of the file
                    logging.info(f"Monitoring log file: {self.log_file_path}")
                    while True:
                        line = log_file.readline()
                        if not line:
                            time.sleep(1)  # Wait before checking again
                            continue
                        self.process_log_line(line)
            except FileNotFoundError:
                logging.error(f"Log file not found: {self.log_file_path}. Retrying...")
                retries += 1
                time.sleep(5)
            except Exception as e:
                logging.error(f"Error monitoring container escape logs: {e}")
                retries += 1
                time.sleep(5)

        if retries == max_retries:
            logging.critical(
                "Max retries reached. Unable to monitor container escape logs."
            )

    def process_log_line(self, line):
        logging.debug(f"Processing log line: {line.strip()}")
        # Check for suspicious keywords in the log line
        if any(keyword in line.lower() for keyword in self.suspicious_keywords):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: {self.current_user} - Suspicious activity detected: {line.strip()}"
            # Send alerts for suspicious activity
            for alert in self.alerts:
                alert.send_alert("Container Escape Attempt", message)
            logging.warning(message)
