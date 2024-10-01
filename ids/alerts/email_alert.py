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
        self.buffered_logs = []  # List to store logs temporarily
        self.last_email_time = time.time()  # To track when to send the next email
        self.email_interval = 15 * 60  # 15 minutes in seconds
        logging.info("EmailAlert initialized.")

    def buffer_log(self, log_message):
        """Buffers log messages until it's time to send the email."""
        self.buffered_logs.append(log_message)

    def send_periodic_email(self):
        """Checks whether 15 minutes have passed, then sends the email with aggregated logs."""
        current_time = time.time()
        if current_time - self.last_email_time >= self.email_interval:
            self.send_aggregated_email()
            self.last_email_time = current_time  # Update the last email sent time

    def send_aggregated_email(self):
        """Sends an email containing the buffered logs or a 'no activity' message."""
        if not self.enabled:
            logging.info("Email alerts are disabled.")
            return

        # If there are no logs, send a 'no recent activity' message
        if not self.buffered_logs:
            subject = "Log Update"
            message = "No recent events logged, check the log file to verify."
        else:
            subject = "Log Update"
            message = "\n".join(self.buffered_logs)  # Combine all log messages

        self.send_email(subject, message)
        self.buffered_logs = []  # Clear the log buffer after sending the email

    def send_alert(self, subject, message):
        """Send an immediate alert email."""
        if self.enabled:
            self.send_email(subject, message)

    def send_email(self, subject, message, retries=3, retry_delay=5):
        """Handles the actual email sending."""
        logging.info(f"Attempting to send email alert with subject: {subject}.")
        try_count = 0

        while try_count < retries:
            try:
                msg = MIMEText(message)
                msg["Subject"] = subject
                msg["From"] = EMAIL_FROM
                msg["To"] = EMAIL_TO

                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                    server.starttls()
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                    server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
                    logging.info("Email alert sent successfully.")
                    break

            except Exception as e:
                try_count += 1
                logging.error(f"Failed to send email alert (Attempt {try_count}): {e}")
                if try_count < retries:
                    logging.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"Failed to send email after {retries} attempts.")
