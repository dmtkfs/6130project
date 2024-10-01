from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import logging
import time
from ids.config import (
    CRITICAL_PATHS,
    EXCLUDED_DIRS,
)  # Import critical paths and excluded dirs


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("FileSystemMonitorHandler initialized.")

    def on_any_event(self, event):
        event_src_path = os.path.realpath(event.src_path)
        logging.info(f"Detected event: {event.event_type} on {event_src_path}")

        if any(event_src_path.startswith(excluded) for excluded in EXCLUDED_DIRS):
            logging.debug(f"Excluded path detected: {event_src_path}")
            return  # Ignore excluded paths

        if any(event_src_path.startswith(critical) for critical in CRITICAL_PATHS):
            if event.event_type in ["created", "deleted", "modified", "moved"]:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                message = (
                    f"{timestamp} - Critical file {event.event_type}: {event_src_path}"
                )
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert(f"Critical File {event.event_type}", message)


def start_file_system_monitor(alerts):
    event_handler = FileSystemMonitorHandler(alerts)
    observer = Observer()
    for path in set(os.path.dirname(p) for p in CRITICAL_PATHS):
        if os.path.exists(path):
            observer.schedule(event_handler, path=path, recursive=True)
            logging.info(f"Scheduled monitoring on path: {path}")
        else:
            logging.warning(f"Critical path directory does not exist: {path}")
    observer.start()
    logging.info("FileSystemMonitor started.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
