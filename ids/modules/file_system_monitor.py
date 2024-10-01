import logging
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, log_alert, email_alert):
        """Initialize the FileSystemMonitorHandler with log and email alerts."""
        self.log_alert = log_alert  # LogAlert for logging
        self.email_alert = email_alert  # EmailAlert for email notifications
        logging.info("FileSystemMonitorHandler initialized.")

    def on_any_event(self, event):
        """Handle any filesystem event."""
        try:
            event_type = event.event_type
            event_src_path = event.src_path
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"{event_time} - Detected event: {event_type} on {event_src_path}"
            logging.info(message)

            # Log the event
            self.log_alert.send_alert("File System Event Detected", message)

            # Buffer the event for email alert
            self.email_alert.buffer_log(message)

        except Exception as e:
            logging.error(f"Error handling file system event: {e}")


def start_file_system_monitor(log_alert, email_alert):
    """Start the file system monitor."""
    try:
        event_handler = FileSystemMonitorHandler(log_alert, email_alert)
        observer = Observer()
        observer.schedule(
            event_handler, path="/etc", recursive=True  # Adjust path as necessary
        )
        observer.start()
        logging.info("FileSystemMonitor started.")

        # Keep monitoring in the main thread
        while True:
            time.sleep(5)

    except Exception as e:
        logging.error(f"FileSystemMonitor encountered an error: {e}")
    finally:
        observer.stop()
        observer.join()
