# ids/alerts/email_alert.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ids.config import EMAIL_ENABLED, SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO
import logging

class EmailAlert:
    def send_alert(self, subject, message):
        if not EMAIL_ENABLED:
            logging.info("Email alerts are disabled.")
            return
        if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO]):
            logging.error("Missing email configuration environment variables.")
            return
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_FROM
            msg['To'] = ', '.join(EMAIL_TO) if isinstance(EMAIL_TO, list) else EMAIL_TO
            msg['Subject'] = subject
            msg.attach(MIMEText(message, 'plain'))

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
            logging.info(f"Email sent: {subject}")
        except Exception as e:
            logging.error(f"Failed to send email: {e}")
