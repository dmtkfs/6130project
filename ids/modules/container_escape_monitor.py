# ids/modules/container_escape_monitor.py

import logging
import os
import time

class ContainerEscapeMonitor:
    def __init__(self, alerts, log_file_path='/host_var_log/auth.log'):
        self.alerts = alerts
        self.log_file_path = log_file_path
        logging.info("ContainerEscapeMonitor initialized.")

    def start(self):
        logging.info(f"Starting ContainerEscapeMonitor on {self.log_file_path}")
        try:
            with open(self.log_file_path, 'r') as log_file:
                log_file.seek(0, os.SEEK_END)  # Move to the end of the file
                logging.info(f"Monitoring log file: {self.log_file_path}")
                while True:
                    line = log_file.readline()
                    if not line:
                        time.sleep(1)  # Wait before checking again
                        continue
                    self.process_log_line(line)
        except Exception as e:
            logging.error(f"Failed to monitor container escape logs: {e}")

    def process_log_line(self, line):
        logging.debug(f"Processing log line: {line.strip()}")
        # Define patterns or keywords that indicate a container escape attempt
        suspicious_keywords = ['container escape', 'access denied', 'unauthorized access']
        if any(keyword in line.lower() for keyword in suspicious_keywords):
            message = f"Suspicious activity detected in logs: {line.strip()}"
            for alert in self.alerts:
                alert.send_alert("Container Escape Attempt", message)
            logging.warning(message)
