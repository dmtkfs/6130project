# ids/modules/container_escape_monitor.py

import logging
import os
import time
import getpass  # To capture user details
import subprocess


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        """
        Initialize the ContainerEscapeMonitor class with the alerts
        to send in case of a container escape attempt.
        """
        self.alerts = alerts
        self.sensitive_paths = [
            "/host_root",
            "/proc/host",
            # Add more sensitive paths as needed
        ]
        self.monitor_interval = 5  # seconds
        logging.debug("ContainerEscapeMonitor initialized.")

    def start(self):
        """
        Start monitoring the container for escape attempts or unauthorized actions.
        """
        logging.info("ContainerEscapeMonitor started.")
        try:
            while True:
                self.check_sensitive_paths()
                self.monitor_sudo_attempts()
                time.sleep(self.monitor_interval)
        except Exception as e:
            logging.error(f"ContainerEscapeMonitor encountered an error: {e}")

    def check_sensitive_paths(self):
        """
        Check if any unauthorized access to sensitive paths is happening.
        """
        for path in self.sensitive_paths:
            if os.path.exists(path):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                message = f"{timestamp} - ContainerEscapeMonitor - Potential container escape attempt detected: Accessed {path}"
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert("Container Escape Attempt Detected", message)

    def monitor_sudo_attempts(self):
        """
        Monitor if the 'sudo' command is used inside the container by checking recent sudo sessions.
        """
        try:
            # Check for active sudo sessions
            result = subprocess.run(
                ["pgrep", "-fl", "sudo"], stdout=subprocess.PIPE, text=True
            )
            if result.stdout.strip():
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                message = f"{timestamp} - ContainerEscapeMonitor - 'sudo' command detected: {result.stdout.strip()}"
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert("Container Escape Attempt Detected", message)
        except Exception as e:
            logging.error(f"Error monitoring sudo commands: {e}")
