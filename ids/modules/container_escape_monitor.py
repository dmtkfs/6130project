import logging
import os
import time


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("ContainerEscapeMonitor initialized.")

    def start(self):
        logging.info("ContainerEscapeMonitor started.")
        try:
            while True:
                self.monitor_container_escape()
                time.sleep(5)
        except Exception as e:
            logging.error(f"ContainerEscapeMonitor encountered an error: {e}")

    def monitor_container_escape(self):
        if os.path.exists("/path_to_sensitive_host_file"):
            message = "Potential container escape attempt detected!"
            logging.warning(message)
            for alert in self.alerts:
                alert.send_alert("Container Escape Detected", message)
