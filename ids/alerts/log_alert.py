import logging


class LogAlert:
    def __init__(self):
        logging.info("LogAlert initialized.")

    def send_alert(self, subject, message, level=logging.WARNING):
        # Log the message with the correct severity level
        if level == logging.CRITICAL:
            logging.critical(f"{subject} - {message}")
        elif level == logging.ERROR:
            logging.error(f"{subject} - {message}")
        elif level == logging.WARNING:
            logging.warning(f"{subject} - {message}")
        else:
            logging.info(f"{subject} - {message}")
