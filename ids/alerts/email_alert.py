# ids/alerts/email_alert.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ids.config import EMAIL_ENABLED, SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO
import logging

class EmailAlert:
    def send_alert(self, subject, message):
        if not EMAIL_ENABLED:
            return
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_FROM
            msg['To'] = ', '.join(EMAIL_TO)
            msg['Subject'] = subject
            msg.attach(MIMEText(message, 'plain'))

            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
            server.quit()
            logging.info(f"Email sent: {subject}")
        except Exception as e:
            logging.error(f"Failed to send email: {e}")
