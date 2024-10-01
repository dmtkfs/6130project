import time
import logging
from ids.config import CONTAINER_SSH_LOG_FILE_PATH, HOST_SSH_LOG_FILE_PATH
from datetime import datetime


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.log_file_positions = {
            CONTAINER_SSH_LOG_FILE_PATH: 0,
            HOST_SSH_LOG_FILE_PATH: 0,
        }
        logging.info("SSHMonitor initialized.")

    def start(self):
        logging.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs(CONTAINER_SSH_LOG_FILE_PATH, "Container SSH")
                self.monitor_ssh_logs(HOST_SSH_LOG_FILE_PATH, "Host SSH")
                time.sleep(5)
        except Exception as e:
            logging.error(f"SSHMonitor encountered an error: {e}")

    def monitor_ssh_logs(self, log_file_path, source):
        try:
            with open(log_file_path, "r") as log_file:
                log_file.seek(self.log_file_positions.get(log_file_path, 0))

                for line in log_file:
                    if "Failed" in line or "Accepted" in line:
                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        message = f"{event_time} - {source} SSH log: {line.strip()}"
                        logging.critical(message)

                        # Buffer the log for email later
                        for alert in self.alerts:
                            if hasattr(alert, "buffer_log"):
                                alert.buffer_log(message)

                self.log_file_positions[log_file_path] = log_file.tell()
        except Exception as e:
            logging.error(f"Error reading SSH logs from {log_file_path}: {e}")
