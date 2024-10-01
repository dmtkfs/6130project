import time
import logging
from ids.config import LOG_FILE_PATH  # Only use the centralized log file path


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.log_file_positions = {}  # Store last read positions
        logging.debug("SSHMonitor initialized.")

    def start(self):
        logging.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs(LOG_FILE_PATH, "Host")
                self.monitor_ssh_logs(LOG_FILE_PATH, "Container")
                time.sleep(5)
        except Exception as e:
            logging.error(f"SSHMonitor encountered an error: {e}")

    def monitor_ssh_logs(self, log_file_path, source):
        try:
            with open(log_file_path, "r") as log_file:
                last_position = self.log_file_positions.get(log_file_path, 0)
                log_file.seek(last_position)

                for line in log_file:
                    if "Failed" in line or "Accepted" in line:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        message = f"{timestamp} - {source} SSH log: {line.strip()}"
                        logging.warning(message)
                        for alert in self.alerts:
                            alert.send_alert(f"{source} SSH Activity Detected", message)

                self.log_file_positions[log_file_path] = log_file.tell()
        except Exception as e:
            logging.error(f"Error reading SSH logs from {log_file_path}: {e}")
