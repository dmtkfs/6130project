import logging
import os
import time
import subprocess
from ids.config import LOG_FILE_PATH  # Import centralized log file path


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.sensitive_paths = [
            "/host_root",
            "/proc/host",
<<<<<<< HEAD
        ]
=======
        ]  # Add more sensitive paths as needed
        self.monitor_interval = 5  # seconds
>>>>>>> 154415a767f2f928ab03a07112e280b674186eb0
        logging.debug("ContainerEscapeMonitor initialized.")

    def start(self):
        logging.info("ContainerEscapeMonitor started.")
        try:
            while True:
                self.check_sensitive_paths()
                self.monitor_sudo_attempts()
                time.sleep(5)
        except Exception as e:
            logging.error(f"ContainerEscapeMonitor encountered an error: {e}")

    def check_sensitive_paths(self):
        for path in self.sensitive_paths:
            if os.path.exists(path):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
<<<<<<< HEAD
                message = f"{timestamp} - Accessed {path}. Potential container escape attempt."
=======
                message = f"{timestamp} - Potential container escape attempt detected: Accessed {path}"
>>>>>>> 154415a767f2f928ab03a07112e280b674186eb0
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert("Container Escape Attempt Detected", message)

    def monitor_sudo_attempts(self):
        try:
            result = subprocess.run(
                ["pgrep", "-fl", "sudo"], stdout=subprocess.PIPE, text=True
            )
            if result.stdout.strip():
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                message = (
                    f"{timestamp} - 'sudo' command detected: {result.stdout.strip()}"
                )
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert("Container Escape Attempt Detected", message)
        except Exception as e:
            logging.error(f"Error monitoring sudo commands: {e}")
