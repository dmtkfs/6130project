# ids/alerts/log_alert.py

import logging
import time


class LogAlert:
    def send_alert(self, subject, message):
        """
        Log an alert message with the specified subject and content.
        """
        # Capture current time
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Log the alert with detailed information
        logging.warning(f"{timestamp} - {subject}: {message}")
