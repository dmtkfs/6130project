import psutil
import logging
import time
from datetime import datetime


class ProcessMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.existing_pids = set()  # Track running processes
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
                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.critical(
                    f"Suspicious Process Detected - {event_time} - {proc_info}"
                )
                for alert in self.alerts:
                    alert.send_alert(
                        "Suspicious Process Detected", f"{event_time} - {proc_info}"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
