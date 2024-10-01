import psutil
import logging
import time
from datetime import datetime


class ProcessMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.existing_pids = set()  # Keep track of processes
        logging.info("ProcessMonitor initialized.")

    def start(self):
        logging.info("ProcessMonitor started.")
        try:
            while True:
                self.check_new_processes()
                time.sleep(5)
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")

    def check_new_processes(self):
        current_pids = set(psutil.pids())
        new_pids = current_pids - self.existing_pids
        self.existing_pids = current_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_info = f"PID={pid}, Name={proc.name()}, User={proc.username()}, Cmdline={' '.join(proc.cmdline())}"
                event_time = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )  # Timestamp for event
                logging.info(f"New process detected: {proc_info}")

                # Only send critical alerts for suspicious (root) processes
                if proc.username() == "root":
                    for alert in self.alerts:
                        alert.send_alert(
                            "Suspicious Process Detected",
                            f"{event_time} - {proc_info}",
                            level=logging.CRITICAL,
                        )
                else:
                    for alert in self.alerts:
                        alert.send_alert(
                            "Process Detected",
                            f"{event_time} - {proc_info}",
                            level=logging.INFO,
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
