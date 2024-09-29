# ids/alerts/log_alert.py

import logging

class LogAlert:
    def send_alert(self, subject, message):
        logging.warning(f"{subject}: {message}")
