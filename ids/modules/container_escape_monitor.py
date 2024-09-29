# ids/modules/container_escape_monitor.py

import logging
import os
import time


class ContainerEscapeMonitor:
    def __init__(self, alerts, log_file_path="/host_var_log/auth.log"):
        self.alerts = alerts
        self.log_file_path = log_file_path
        self.suspicious_keywords = [
            "container escape",
            "access denied",
            "unauthorized access",
        ]
        logging.info(
            "ContainerEscapeMonitor initialized with log file path: %s", log_file_path
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
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        # Check for suspicious keywords in the log line
        if any(keyword in line.lower() for keyword in self.suspicious_keywords):
            message = (
                f"{timestamp} - Suspicious activity detected in logs: {line.strip()}"
            )
            for alert in self.alerts:
                alert.send_alert("Container Escape Attempt", message)
            logging.warning(message)

    def add_suspicious_keyword(self, keyword):
        self.suspicious_keywords.append(keyword)
        logging.info(f"Added new suspicious keyword for monitoring: {keyword}")
