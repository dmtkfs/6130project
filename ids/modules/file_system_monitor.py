# modules/file_system_monitor.py

import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import time
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert
from ids.config import CRITICAL_PATHS, EXCLUDED_PATHS


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, alerts):
        super().__init__()
        self.alerts = alerts
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("FileSystemMonitorHandler initialized.")

    def on_any_event(self, event):
        try:
            event_type = event.event_type
            event_src_path = event.src_path

            # Exclude events from EXCLUDED_PATHS
            if any(
                event_src_path.startswith(excl_path) for excl_path in EXCLUDED_PATHS
            ):
                self.logger.debug(
                    f"Ignored event: {event_type} on {event_src_path} as it is in excluded paths."
                )
                return

            # Check if the event path is in critical paths
            if any(event_src_path.startswith(path) for path in CRITICAL_PATHS):
                # Optional: Implement user extraction logic here
                user = self.get_user_from_event(
                    event
                )  # Placeholder for user extraction
                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"User '{user}' performed '{event_type}' on '{event_src_path}' at {event_time}"
                self.logger.info(message)

                for alert in self.alerts:
                    if isinstance(alert, LogAlert):
                        alert.send_alert("File System Event Detected", message)
                    if isinstance(alert, EmailAlert):
                        alert.buffer_log(message)
        except Exception as e:
            self.logger.error(f"Error handling file system event: {e}")

    def get_user_from_event(self, event):
        """
        Placeholder method to extract the user performing the file system event.
        Implementing this requires integration with system audit tools or elevated permissions.
        For now, it returns 'unknown_user'.
        """
        # Implement actual user extraction logic if possible
        return "unknown_user"


def start_file_system_monitor(alerts):
    logger = logging.getLogger("FileSystemMonitor")
    try:
        event_handler = FileSystemMonitorHandler(alerts)
        observer = Observer()

        # Monitor all critical paths
        for path in CRITICAL_PATHS:
            observer.schedule(event_handler, path=path, recursive=False)
            logger.debug(f"Scheduled monitoring on critical path: {path}")

        # If you plan to monitor additional directories, ensure they are excluded
        # Example: Monitoring '/etc/' while excluding certain subdirectories
        # observer.schedule(event_handler, path='/etc/', recursive=True)

        observer.start()
        logger.info("FileSystemMonitor started.")

        while True:
            time.sleep(5)
    except Exception as e:
        logger.error(f"FileSystemMonitor encountered an error: {e}")
    finally:
        observer.stop()
        observer.join()
        logger.info("FileSystemMonitor stopped.")
