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
import time


class EmailAlert:
    def __init__(self):
        self.enabled = EMAIL_ENABLED

    def send_alert(
        self, subject, message, retries=3, retry_delay=5, level=logging.CRITICAL
    ):
        if not self.enabled or level != logging.CRITICAL:
            logging.info("Email alerts are disabled or the alert is not critical.")
            return

        logging.info(f"Attempting to send email alert with subject: {subject}.")
        try_count = 0

        while try_count < retries:
            try:
                msg = MIMEText(message)
                msg["Subject"] = subject
                msg["From"] = EMAIL_FROM
                msg["To"] = EMAIL_TO

                logging.debug(f"Email subject: {subject}")
                logging.debug(f"Email message: {message}")

                # Set up the server
                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                    server.ehlo()  # Can be omitted
                    server.starttls()
                    server.ehlo()  # Can be omitted
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                    server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
                    logging.info("Email alert sent successfully.")
                    break  # If successful, exit the retry loop

            except Exception as e:
                try_count += 1
                logging.error(f"Failed to send email alert (Attempt {try_count}): {e}")
                if try_count < retries:
                    logging.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"Failed to send email after {retries} attempts.")
