import time
import logging
from datetime import datetime
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.log_file_positions = {}
        logging.info("SSHMonitor initialized.")

    def start(self):
        logging.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs(
                    "/var/log/ids_app/ids.log", "Container SSH"
                )  # Unified log file path
                time.sleep(5)
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
                        message = f"SSH: {source} log at {event_time}: {line.strip()}"
                        logging.critical(message)

                        for alert in self.alerts:
                            alert.send_alert("SSH Log Detected", message)

                self.log_file_positions[log_file_path] = log_file.tell()
        except Exception as e:
            logging.error(f"Error reading SSH logs from {log_file_path}: {e}")
