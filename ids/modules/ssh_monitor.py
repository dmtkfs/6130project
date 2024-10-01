import time
import logging
from ids.config import (
    HOST_SSH_LOG_FILE_PATH,
    CONTAINER_SSH_LOG_FILE_PATH,
)  # Import SSH log file paths

# Minimum time between logging the same event (in seconds)
LOG_INTERVAL = 10


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.log_file_positions = {}  # Dictionary to store last read positions
        self.last_logged_events = {}  # Store the last logged SSH events
        logging.debug("SSHMonitor initialized.")

    def start(self):
        logging.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs(HOST_SSH_LOG_FILE_PATH, "Host")
                self.monitor_ssh_logs(CONTAINER_SSH_LOG_FILE_PATH, "Container")
                time.sleep(5)
        except Exception as e:
            logging.error(f"SSHMonitor encountered an error: {e}")

    def monitor_ssh_logs(self, log_file_path, source):
        try:
            # Open the log file in read mode
            with open(log_file_path, "r") as log_file:
                # Get the file position for this log file
                last_position = self.log_file_positions.get(log_file_path, 0)
                log_file.seek(last_position)  # Move to last read position

                for line in log_file:
                    if "Failed" in line or "Accepted" in line:
                        current_time = time.time()
                        event_key = f"{source}-{line.strip()}"  # Create a unique key for the event

                        # Check if the event has been logged within the last LOG_INTERVAL
                        if self.is_event_logged_recently(event_key, current_time):
                            continue  # Skip logging this event again

                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        message = f"{timestamp} - {source} SSH log: {line.strip()}"
                        logging.warning(message)

                        # Send alerts for the SSH activity
                        for alert in self.alerts:
                            alert.send_alert(f"{source} SSH Activity Detected", message)

                        # Update the last logged time for this event
                        self.last_logged_events[event_key] = current_time

                # Update the last read position
                self.log_file_positions[log_file_path] = log_file.tell()
        except Exception as e:
            logging.error(f"Error reading SSH logs from {log_file_path}: {e}")

    def is_event_logged_recently(self, event_key, current_time):
        """
        Check if the event has been logged within the last LOG_INTERVAL seconds.
        """
        last_logged_time = self.last_logged_events.get(event_key)
        if last_logged_time is None or current_time - last_logged_time > LOG_INTERVAL:
            return False
        return True
