# process_monitor.py

import psutil
import logging
import time
from datetime import datetime
from ids.alerts.log_alert import LogAlert  # Ensure LogAlert is imported correctly
from ids.alerts.email_alert import EmailAlert


class ProcessMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.existing_pids = set(
            psutil.pids()
        )  # Initialize with currently running processes
        logging.info("ProcessMonitor initialized.")

    def start(self):
        logging.info("ProcessMonitor started.")
        try:
            while True:
                self.check_new_processes()
                time.sleep(5)  # Adjust the monitoring interval if needed
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")

    def check_new_processes(self):
        """Detect newly started processes."""
        current_pids = set(psutil.pids())  # Get current running processes
        new_pids = (
            current_pids - self.existing_pids
        )  # Compare with the known existing ones
        self.existing_pids = current_pids  # Update the existing set

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_info = f"PID={pid}, Name={proc.name()}, User={proc.username()}, Cmdline={' '.join(proc.cmdline())}"
                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"New Process Detected - {event_time} - {proc_info}"

                for alert in self.alerts:
                    if isinstance(alert, LogAlert):  # Check if it's LogAlert
                        alert.send_alert("New Process Detected", message)

                    if isinstance(alert, EmailAlert):  # Buffer for email alerts
                        alert.buffer_log(message)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
