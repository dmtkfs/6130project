# modules/process_monitor.py

import psutil
import logging
import time
from datetime import datetime
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert
from ids.config import SUSPICIOUS_COMMANDS


class ProcessMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.existing_pids = set(
            psutil.pids()
        )  # Initialize with currently running processes
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("ProcessMonitor initialized.")

    def start(self):
        self.logger.info("ProcessMonitor started.")
        try:
            while True:
                self.check_new_processes()
                time.sleep(5)  # Adjust the monitoring interval if needed
        except Exception as e:
            self.logger.error(f"ProcessMonitor encountered an error: {e}")

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
                cmdline = proc.cmdline()
                command = cmdline[0] if cmdline else ""
                # Check if command is suspicious
                if any(susp_cmd in command for susp_cmd in SUSPICIOUS_COMMANDS):
                    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    user = proc.username()
                    message = f"User '{user}' started suspicious process '{proc.name()}' (PID={pid}) with command: {' '.join(cmdline)} at {event_time}"

                    self.logger.warning(message)

                    for alert in self.alerts:
                        if isinstance(alert, LogAlert):
                            alert.send_alert("Suspicious Process Detected", message)
                        if isinstance(alert, EmailAlert):
                            alert.buffer_log(message)

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.debug(f"Process PID {pid} could not be accessed: {e}")
                continue
