# ids/modules/file_system_monitor.py

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import logging
import time


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, critical_paths, excluded_dirs, alerts):
        self.alerts = alerts
        self.critical_paths = [os.path.realpath(path) for path in critical_paths]
        self.excluded_dirs = [os.path.realpath(path) for path in excluded_dirs]
        logging.debug("FileSystemMonitorHandler initialized.")

    def on_any_event(self, event):
        event_src_path = os.path.realpath(event.src_path)
        logging.debug(f"Detected event: {event.event_type} on {event_src_path}")

        if any(event_src_path.startswith(excluded) for excluded in self.excluded_dirs):
            logging.debug(f"Excluded path detected: {event_src_path}")
            return  # Ignore excluded paths

        if any(event_src_path.startswith(critical) for critical in self.critical_paths):
            if event.event_type in ["created", "deleted", "modified", "moved"]:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                try:
                    # Attempt to get the owner of the file
                    file_stat = os.stat(event_src_path)
                    process_owner = (
                        os.getlogin()
                    )  # Note: os.getlogin() may raise an exception in some contexts
                    # To get the actual user, more advanced monitoring is needed (e.g., auditd)
                except Exception:
                    process_owner = "Unknown"

                message = f"{timestamp} - User: {process_owner} - Critical file {event.event_type}: {event_src_path}"
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert(f"Critical File {event.event_type}", message)


class FileSystemMonitor:
    def __init__(self, critical_paths, excluded_dirs, alerts):
        self.critical_paths = critical_paths
        self.excluded_dirs = excluded_dirs
        self.alerts = alerts
        logging.debug("FileSystemMonitor initialized.")

    def start(self):
        event_handler = FileSystemMonitorHandler(
            self.critical_paths, self.excluded_dirs, self.alerts
        )
        observer = Observer()
        # Monitor only critical directories to optimize performance
        monitored_dirs = set(os.path.dirname(path) for path in self.critical_paths)
        for path in monitored_dirs:
            if os.path.exists(path):
                observer.schedule(event_handler, path=path, recursive=True)
                logging.debug(f"Scheduled monitoring on path: {path}")
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
