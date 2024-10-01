# log_alert.py

import logging


class LogAlert:
    def __init__(self):
        logging.info("LogAlert initialized.")

    def send_alert(self, subject, message):
        """Log the alert message to system logs."""
        logging.warning(f"{subject} - {message}")
