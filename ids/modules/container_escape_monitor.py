import logging
import time
from datetime import datetime


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("ContainerEscapeMonitor initialized.")

    def start(self):
        logging.info("ContainerEscapeMonitor started.")
        try:
            while True:
                self.detect_escape_attempts()
                time.sleep(5)
        except Exception as e:
            logging.error(f"ContainerEscapeMonitor encountered an error: {e}")

    def detect_escape_attempts(self):
        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"{event_time} - Potential container escape attempt detected."
        logging.warning(message)
        for alert in self.alerts:
            alert.send_alert("Container Escape Attempt Detected", message)
