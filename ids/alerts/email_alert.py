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
from collections import defaultdict
from datetime import datetime, timedelta
import threading


class EmailAlert:
    def __init__(self, rate_limit=5, rate_period=300, aggregate_interval=600):
        """
        Initialize rate limiting and aggregation parameters.
        :param rate_limit: Maximum number of emails allowed within rate_period.
        :param rate_period: Time window in seconds for rate limiting.
        :param aggregate_interval: Time window in seconds to aggregate alerts.
        """
        self.rate_limit = rate_limit
        self.rate_period = rate_period
        self.aggregate_interval = aggregate_interval
        self.email_timestamps = defaultdict(list)  # {subject: [timestamps]}
        self.alert_queue = defaultdict(list)  # {subject: [messages]}
        self.lock = threading.Lock()

        # Start the aggregation thread
        self.aggregation_thread = threading.Thread(
            target=self.aggregate_alerts, daemon=True
        )
        self.aggregation_thread.start()

    def send_alert(self, subject, message):
        """
        Queue an alert message for aggregation and sending.
        """
        if not EMAIL_ENABLED:
            logging.info("Email alerts are disabled.")
            return

        if not all(
            [SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO]
        ):
            logging.error("Missing email configuration environment variables.")
            return

        with self.lock:
            self.alert_queue[subject].append(message)

    def aggregate_alerts(self):
        """
        Periodically aggregates and sends accumulated alerts.
        """
        while True:
            time.sleep(self.aggregate_interval)
            with self.lock:
                for subject, messages in list(self.alert_queue.items()):
                    if messages:
                        aggregated_message = "\n\n".join(messages)
                        self._send_email(subject, aggregated_message)
                        self.alert_queue[subject] = []

    def _send_email(self, subject, message):
        """
        Send an aggregated email alert if rate limiting allows.
        """
        current_time = datetime.now()
        # Clean up old timestamps
        self.email_timestamps[subject] = [
            ts
            for ts in self.email_timestamps[subject]
            if current_time - ts < timedelta(seconds=self.rate_period)
        ]

        if len(self.email_timestamps[subject]) >= self.rate_limit:
            logging.warning(
                f"Rate limit exceeded for subject '{subject}'. Email not sent."
            )
            return

        try:
            # Log the attempt to send an email
            logging.debug(f"Attempting to send aggregated email: {subject}")

            # Capture current time for detailed logging
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            # Prepare the email content
            msg = MIMEMultipart()
            msg["From"] = EMAIL_FROM
            msg["To"] = ", ".join(EMAIL_TO) if isinstance(EMAIL_TO, list) else EMAIL_TO
            msg["Subject"] = subject
            detailed_message = f"Timestamp: {timestamp}\n\n{message}"
            msg.attach(MIMEText(detailed_message, "plain"))

            # Connect to the SMTP server and send the email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()  # Secure the connection
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

            logging.info(f"Aggregated email sent: {subject} at {timestamp}")

            # Record the timestamp
            self.email_timestamps[subject].append(current_time)

        except Exception as e:
            logging.error(f"Failed to send aggregated email: {e}")
