# modules/ssh_monitor.py

import time
import logging
from datetime import datetime
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert
import re
from ids.config import LOG_FILE_PATH


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.log_file_positions = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("SSHMonitor initialized.")

    def start(self):
        self.logger.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs(
                    LOG_FILE_PATH, "Container SSH"
                )  # Unified log file path
                time.sleep(5)
        except Exception as e:
            self.logger.error(f"SSHMonitor encountered an error: {e}")

    def monitor_ssh_logs(self, log_file_path, source):
        """Monitor logs for SSH activity."""
        try:
            with open(log_file_path, "r") as log_file:
                last_position = self.log_file_positions.get(log_file_path, 0)
                log_file.seek(last_position)

                for line in log_file:
                    if "Failed" in line or "Accepted" in line:
                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        parsed_message = self.parse_ssh_log(line, event_time, source)
                        if parsed_message:
                            message = parsed_message
                            self.logger.critical(message)

                            for alert in self.alerts:
                                if isinstance(alert, LogAlert):
                                    alert.send_alert("SSH Activity Detected", message)
                                if isinstance(alert, EmailAlert):
                                    alert.buffer_log(message)

                self.log_file_positions[log_file_path] = log_file.tell()
        except Exception as e:
            self.logger.error(f"Error reading SSH logs from {log_file_path}: {e}")

    def parse_ssh_log(self, line, event_time, source):
        """Parse SSH log lines to extract user and action."""
        accepted_pattern = r"Accepted\s+\w+\s+for\s+(\w+)\s+from\s+([\d\.]+)"
        failed_pattern = r"Failed\s+\w+\s+for\s+(\w+)\s+from\s+([\d\.]+)"

        accepted_match = re.search(accepted_pattern, line)
        failed_match = re.search(failed_pattern, line)

        if accepted_match:
            user, ip = accepted_match.groups()
            action = "successful login"
        elif failed_match:
            user, ip = failed_match.groups()
            action = "failed login attempt"
        else:
            user, ip, action = "unknown", "unknown", "unknown action"

        return f"User '{user}' from IP '{ip}' performed '{action}' at {event_time} via {source}."
