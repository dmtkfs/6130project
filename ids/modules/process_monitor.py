import psutil
import logging
import time
from datetime import datetime
from ids.alerts.log_alert import LogAlert
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
                user = proc.username()
                cmdline = " ".join(proc.cmdline())
                process_name = proc.name()

                if "sudo" in cmdline or "su" in cmdline:  # Suspicious processes
                    message = f"Process: {user} started {process_name} with cmdline: {cmdline}"
                    logging.warning(message)

                    for alert in self.alerts:
                        alert.send_alert("New Process Detected", message)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
