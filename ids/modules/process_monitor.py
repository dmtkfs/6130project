import psutil
import time
import logging
import getpass  # To capture user details
from ids.config import LOG_FILE_PATH  # Import centralized log file path


class ProcessMonitor:
    def __init__(self, alerts, poll_interval=5):
        self.alerts = alerts
        self.poll_interval = poll_interval
        self.known_pids = set()
        logging.info(f"ProcessMonitor initialized with log file path: {LOG_FILE_PATH}")

    def start(self):
        logging.info("ProcessMonitor started.")
        self.known_pids = set(psutil.pids())

        try:
            while True:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self.known_pids
                if new_pids:
                    for pid in new_pids:
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()

                            if process_name not in [
                                "sshd",
                                "bash",
                                "sh",
                                "supervisord",
                            ]:
                                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                                process_owner = proc.username()
                                process_info = f"{timestamp} - User: {process_owner} - New process detected: PID={proc.pid}, Name={process_name}, Cmdline={' '.join(proc.cmdline())}"

                                logging.info(process_info)

                                # Trigger alerts only for critical processes
                                if process_owner == "root":
                                    logging.warning(
                                        f"Suspicious root process detected: {process_info}"
                                    )
                                    for alert in self.alerts:
                                        alert.send_alert(
                                            "Suspicious Process Detected", process_info
                                        )

                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            logging.warning(
                                f"{timestamp} - Permission denied or process does not exist for PID={pid}: {e}"
                            )
                self.known_pids = current_pids
                time.sleep(self.poll_interval)
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")
