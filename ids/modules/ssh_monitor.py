import time
import logging
from datetime import datetime


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.log_file_positions = {
            "/var/log/supervisor/sshd_stdout.log": 0,  # Container SSH log file
            "/host_var_log/auth.log": 0,  # Host SSH log file
        }
        logging.info("SSHMonitor initialized.")

    def start(self):
        logging.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs(
                    "/var/log/supervisor/sshd_stdout.log", "Container SSH"
                )
                self.monitor_ssh_logs("/host_var_log/auth.log", "Host SSH")
                time.sleep(5)
        except Exception as e:
            logging.error(f"SSHMonitor encountered an error: {e}")

    def monitor_ssh_logs(self, log_file_path, source):
        try:
            with open(log_file_path, "r") as log_file:
                # Move to the last known position
                last_position = self.log_file_positions.get(log_file_path, 0)
                log_file.seek(last_position)

                # Read new lines
                for line in log_file:
                    if "Failed" in line or "Accepted" in line:
                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        message = f"{event_time} - {source} SSH log: {line.strip()}"
                        logging.critical(message)

                        # Buffer the log for email later
                        for alert in self.alerts:
                            if hasattr(alert, "buffer_log"):
                                alert.buffer_log(message)

                # Update file position
                self.log_file_positions[log_file_path] = log_file.tell()
        except Exception as e:
            logging.error(f"Error reading SSH logs from {log_file_path}: {e}")
