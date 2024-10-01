import logging


class LogAlert:
    def __init__(self):
        logging.info("LogAlert initialized.")

    def send_alert(self, subject, message):
        logging.warning(f"{subject} - {message}")
