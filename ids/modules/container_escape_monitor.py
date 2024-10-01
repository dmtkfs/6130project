# modules/container_escape_monitor.py

import logging
import psutil
from datetime import datetime
import time
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert
from ids.config import SUSPICIOUS_COMMANDS


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("ContainerEscapeMonitor initialized.")

    def get_process_info(self, process):
        """Retrieve process information."""
        try:
            return process.username(), process.cmdline()
        except Exception as e:
            self.logger.error(
                f"Failed to retrieve process info for PID {process.pid}: {e}"
            )
            return None, None

    def check_privilege_escalation(self, user, cmdline):
        """Check for privilege escalation attempts inside the container."""
        if any(susp_cmd in cmdline for susp_cmd in SUSPICIOUS_COMMANDS):
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"User '{user}' attempted privilege escalation using command: {' '.join(cmdline)} at {event_time}"
            self.logger.critical(message)

            for alert in self.alerts:
                if isinstance(alert, LogAlert):  # Check if it's LogAlert
                    alert.send_alert("Privilege Escalation Detected", message)

                if hasattr(alert, "buffer_log"):  # Buffer for email alerts
                    alert.buffer_log(message)

    def check_container_escape(self, user, cmdline):
        """Detect potential container escape attempts."""
        escape_patterns = ["/host/", "nsenter"]
        if any(pattern in cmdline for pattern in escape_patterns):
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"User '{user}' attempted container escape using command: {' '.join(cmdline)} at {event_time}"
            self.logger.critical(message)

            for alert in self.alerts:
                if isinstance(alert, LogAlert):  # Check if it's LogAlert
                    alert.send_alert("Container Escape Attempt Detected", message)

                if hasattr(alert, "buffer_log"):  # Buffer for email alerts
                    alert.buffer_log(message)

    def monitor_processes(self):
        """Monitor all running processes inside the container."""
        for process in psutil.process_iter(["pid", "username", "cmdline"]):
            user, cmdline = self.get_process_info(process)

            if user and cmdline:
                self.check_privilege_escalation(user, cmdline)
                self.check_container_escape(user, cmdline)

    def start(self):
        self.logger.info("ContainerEscapeMonitor started.")
        while True:
            self.monitor_processes()
            time.sleep(5)  # Adjust the monitoring interval if needed
