# ids/alerts/log_alert.py

import logging
import time
import getpass  # To capture user details


class LogAlert:
    def send_alert(self, subject, message):
        """
        Log an alert message with the specified subject and content.
        """
        # Capture current time and user details
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        current_user = getpass.getuser()  # Get the current user

        # Log the alert with detailed information
        logging.warning(f"{timestamp} - User: {current_user} - {subject}: {message}")
