import logging
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("FileSystemMonitorHandler initialized.")

    def on_any_event(self, event):
        try:
            event_type = event.event_type
            event_src_path = event.src_path
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"{event_time} - Detected event: {event_type} on {event_src_path}"
            logging.info(message)

            for alert in self.alerts:
                if isinstance(alert, LogAlert):  # Check if it's LogAlert
                    alert.send_alert("File System Event Detected", message)

                if isinstance(alert, EmailAlert):  # Buffer for email alerts
                    alert.buffer_log(message)

        except Exception as e:
            logging.error(f"Error handling file system event: {e}")


def start_file_system_monitor(alerts):
    try:
        event_handler = FileSystemMonitorHandler(alerts)
        observer = Observer()
        observer.schedule(
            event_handler, path="/etc", recursive=True
        )  # Adjust path as necessary
        observer.start()
        logging.info("FileSystemMonitor started.")

        while True:
            time.sleep(5)
    except Exception as e:
        logging.error(f"FileSystemMonitor encountered an error: {e}")
    finally:
        observer.stop()
        observer.join()
