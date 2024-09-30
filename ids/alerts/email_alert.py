# ids/alerts/email_alert.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ids.config import (
    EMAIL_ENABLED,
    SMTP_SERVER,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    EMAIL_FROM,
    EMAIL_TO,
)
import logging
import time
import getpass  # To capture user information


class EmailAlert:
    def send_alert(self, subject, message):
        """
        Send an email alert if email functionality is enabled and all configuration
        settings are correctly provided via environment variables.
        """
        if not EMAIL_ENABLED:
            logging.info("Email alerts are disabled.")
            return

        if not all(
            [SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO]
        ):
            logging.error("Missing email configuration environment variables.")
            return

        try:
            # Capture current time and user details for detailed logging
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            current_user = getpass.getuser()

            # Prepare the email content
            msg = MIMEMultipart()
            msg["From"] = EMAIL_FROM
            msg["To"] = ", ".join(EMAIL_TO) if isinstance(EMAIL_TO, list) else EMAIL_TO
            msg["Subject"] = subject
            detailed_message = (
                f"Timestamp: {timestamp}\nUser: {current_user}\n\n{message}"
            )
            msg.attach(MIMEText(detailed_message, "plain"))

            # Connect to the SMTP server and send the email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()  # Secure the connection
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

            logging.info(f"Email sent: {subject} by {current_user} at {timestamp}")

        except Exception as e:
            logging.error(f"Failed to send email: {e}")
