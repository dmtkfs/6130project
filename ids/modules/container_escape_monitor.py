import logging
import os
import time
import getpass


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.container_log_file_path = os.getenv(
            "LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )  # Updated log path
        self.host_log_file_path = os.getenv("HOST_LOG_FILE_PATH", "/var/log/auth.log")
        self.alerts = alerts
        logging.info(
            f"ContainerEscapeMonitor initialized with log file path: {self.container_log_file_path}"
        )

    def start(self):
        logging.info("Starting ContainerEscapeMonitor")
        threading.Thread(
            target=self.monitor_escape_attempts,
            args=(self.container_log_file_path, "Container"),
        ).start()
        threading.Thread(
            target=self.monitor_escape_attempts, args=(self.host_log_file_path, "Host")
        ).start()

    def monitor_escape_attempts(self, log_path, source):
        retries = 0
        max_retries = 5
        while retries < max_retries:
            try:
                with open(log_path, "r") as log_file:
                    log_file.seek(0, os.SEEK_END)  # Move to the end of the file
                    logging.info(
                        f"Monitoring {source} log file for container escape attempts: {log_path}"
                    )
                    while True:
                        line = log_file.readline()
                        if not line:
                            time.sleep(1)
                            continue
                        self.process_log_line(line, source)
            except FileNotFoundError:
                logging.error(f"Log file not found: {log_path}. Retrying...")
                retries += 1
                time.sleep(5)
            except Exception as e:
                logging.error(f"Error monitoring container escape logs: {e}")
                retries += 1
                time.sleep(5)

    def process_log_line(self, line, source):
        logging.debug(f"Processing {source} log line: {line.strip()}")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        current_user = getpass.getuser()

        if "detected container escape" in line.lower():
            message = f"{timestamp} - User: {current_user} - Suspicious activity detected in {source}: {line.strip()}"
            for alert in self.alerts:
                alert.send_alert("Container Escape Attempt", message)
            logging.warning(message)
