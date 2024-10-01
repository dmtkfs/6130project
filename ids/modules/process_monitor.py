import psutil
import logging
import time
from datetime import datetime


class ProcessMonitor:
    def __init__(self, log_alert, email_alert):
        """Initialize the ProcessMonitor with log and email alerts."""
        self.log_alert = log_alert  # LogAlert for logging
        self.email_alert = email_alert  # EmailAlert for email notifications
        self.existing_pids = set(
            psutil.pids()
        )  # Initialize with currently running processes
        logging.info("ProcessMonitor initialized.")

    def start(self):
        """Start monitoring processes."""
        logging.info("ProcessMonitor started.")
        try:
            while True:
                self.check_new_processes()
                time.sleep(5)  # Adjust the monitoring interval if needed
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")

    def check_new_processes(self):
        """Detect newly started processes."""
        current_pids = set(psutil.pids())  # Get currently running processes
        new_pids = (
            current_pids - self.existing_pids
        )  # Compare with the known existing ones
        self.existing_pids = current_pids  # Update the existing set

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_info = f"PID={pid}, Name={proc.name()}, User={proc.username()}, Cmdline={' '.join(proc.cmdline())}"
                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"New Process Detected - {event_time} - {proc_info}")

                # Log the event
                self.log_alert.send_alert(
                    "New Process Detected", f"{event_time} - {proc_info}"
                )

                # Buffer the event for email alert
                self.email_alert.buffer_log(
                    f"New Process Detected - {event_time} - {proc_info}"
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
