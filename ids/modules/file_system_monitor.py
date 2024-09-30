# ids/modules/file_system_monitor.py

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import logging
import time
import getpass  # To capture user details


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, critical_paths, excluded_dirs, alerts):
        self.alerts = alerts
        self.critical_paths = [os.path.realpath(path) for path in critical_paths]
        self.excluded_dirs = [os.path.realpath(path) for path in excluded_dirs]

    def on_any_event(self, event):
        event_src_path = os.path.realpath(event.src_path)
        if any(event_src_path.startswith(excluded) for excluded in self.excluded_dirs):
            # Do NOT log or process excluded path events
            return  # Early exit for excluded paths

        # Only process critical events
        if any(event_src_path.startswith(critical) for critical in self.critical_paths):
            if event.event_type in ["created", "deleted", "modified", "moved"]:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                current_user = getpass.getuser()
                message = f"{timestamp} - User: {current_user} - Critical file {event.event_type}: {event_src_path}"
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert(f"Critical File {event.event_type}", message)
