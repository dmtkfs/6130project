import logging
import psutil
from datetime import datetime
import time


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("ContainerEscapeMonitor initialized.")

    def get_process_info(self, pid):
        """Get process information from PID."""
        try:
            process = psutil.Process(pid)
            return process.username(), process.cmdline()
        except Exception as e:
            logging.error(f"Failed to retrieve process info for PID {pid}: {e}")
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
        """Detect container escape by monitoring access to host system resources."""
        if (
            "escape_attempt_marker" in cmdline
        ):  # Placeholder logic, replace with real detection
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"{event_time} - Container escape attempt detected by {user} (Cmdline: {' '.join(cmdline)})"
            logging.critical(message)
            for alert in self.alerts:
                alert.send_alert("Container Escape Attempt Detected", message)

    def monitor_privilege_escalation_and_escape(self):
        """Monitor container for privilege escalation and escape attempts."""
        for proc in psutil.process_iter(["pid", "username", "cmdline"]):
            user, cmdline = proc.info["username"], proc.info["cmdline"]
            if user and cmdline:
                # Check both privilege escalation and escape attempts
                self.check_privilege_escalation(user, cmdline)
                self.check_container_escape(user, cmdline)

    def start(self):
        logging.info("ContainerEscapeMonitor started.")
        while True:
            try:
                self.monitor_privilege_escalation_and_escape()
            except Exception as e:
                logging.error(f"ContainerEscapeMonitor encountered an error: {e}")

            time.sleep(5)  # Adjust this interval as needed
