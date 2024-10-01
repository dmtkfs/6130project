import time
import logging
from datetime import datetime


class SSHMonitor:
    def __init__(self, log_alert, email_alert):
        """Initialize the SSHMonitor with log and email alerts."""
        self.log_alert = log_alert  # LogAlert for logging
        self.email_alert = email_alert  # EmailAlert for email notifications
        self.log_file_positions = {}
        logging.info("SSHMonitor initialized.")

    def start(self):
        """Start monitoring SSH logs."""
        logging.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs(
                    "/var/log/ids_app/ids.log", "Container SSH"
                )  # Unified log file path
                time.sleep(5)  # Adjust the interval if necessary
        except Exception as e:
            logging.error(f"SSHMonitor encountered an error: {e}")

    def monitor_ssh_logs(self, log_file_path, source):
        """Monitor logs for SSH activity."""
        try:
            with open(log_file_path, "r") as log_file:
                last_position = self.log_file_positions.get(log_file_path, 0)
                log_file.seek(last_position)

                for line in log_file:
                    if "Failed" in line or "Accepted" in line:
                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        message = f"{event_time} - {source} SSH log: {line.strip()}"
                        logging.info(message)

                        # Log the SSH activity
                        self.log_alert.send_alert("SSH Activity Detected", message)

                        # Buffer the event for email alert
                        self.email_alert.buffer_log(message)

                self.log_file_positions[log_file_path] = (
                    log_file.tell()
                )  # Update log file position
        except Exception as e:
            logging.error(f"Error reading SSH logs from {log_file_path}: {e}")
