import logging
import psutil
from datetime import datetime
import time
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("ContainerEscapeMonitor initialized.")

    def get_process_info(self, process):
        """Retrieve process information."""
        try:
            return process.username(), process.cmdline()
        except Exception as e:
            logging.error(f"Failed to retrieve process info for PID {process.pid}: {e}")
            return None, None

    def check_privilege_escalation(self, user, cmdline):
        """Check for privilege escalation attempts inside the container."""
        if "sudo" in cmdline or "su" in cmdline:
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"{event_time} - Privilege escalation attempt by {user} (Cmdline: {' '.join(cmdline)})"
            logging.critical(message)

            for alert in self.alerts:
                alert.send_alert("Privilege Escalation Detected", message)

    def check_container_escape(self, user, cmdline):
        """Detect potential container escape attempts."""
        if "/host/" in cmdline or "nsenter" in cmdline:  # Common escape patterns
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"{event_time} - Container escape attempt by {user} (Cmdline: {' '.join(cmdline)})"
            logging.critical(message)

            for alert in self.alerts:
                alert.send_alert("Container Escape Attempt Detected", message)

    def monitor_processes(self):
        """Monitor all running processes inside the container."""
        for process in psutil.process_iter(["pid", "username", "cmdline"]):
            user, cmdline = self.get_process_info(process)

            if user and cmdline:
                self.check_privilege_escalation(user, cmdline)
                self.check_container_escape(user, cmdline)

    def start(self):
        logging.info("ContainerEscapeMonitor started.")
        while True:
            self.monitor_processes()
            time.sleep(5)  # Adjust the monitoring interval if needed
