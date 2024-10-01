import smtplib
import logging
from email.mime.text import MIMEText
from ids.config import (
    EMAIL_ENABLED,
    SMTP_SERVER,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    EMAIL_FROM,
    EMAIL_TO,
)


class EmailAlert:
    def __init__(self):
        self.enabled = EMAIL_ENABLED

    def send_alert(self, subject, message):
        if not self.enabled:
            logging.info("Email alerts are disabled.")
            return

        logging.info("Attempting to send email alert.")
        try:
            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = EMAIL_FROM
            msg["To"] = EMAIL_TO

            logging.info(f"Sending email with subject: {subject}")

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
                logging.info("Email alert sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")
