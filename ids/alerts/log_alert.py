# alerts/log_alert.py

import logging


class LogAlert:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("LogAlert initialized.")

    def send_alert(self, subject, message):
        """Log the alert message to system logs."""
        self.logger.warning(f"{subject} - {message}")
