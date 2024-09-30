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
        if not any(
            event_src_path.startswith(excluded) for excluded in self.excluded_dirs
        ):
            if event.event_type in ["created", "deleted", "modified", "moved"]:
                if event_src_path in self.critical_paths:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    current_user = getpass.getuser()
                    message = f"{timestamp} - User: {current_user} - Critical file {event.event_type}: {event_src_path}"
                    logging.warning(message)
                    for alert in self.alerts:
                        alert.send_alert(f"Critical File {event.event_type}", message)
                else:
                    logging.info(
                        f"Non-critical file {event.event_type}: {event_src_path}"
                    )
        else:
            logging.info(f"Event on excluded path: {event.src_path}")


class FileSystemMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.critical_paths = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group"]
        self.watch_directories = ["/etc", "/var", "/home", "/tmp"]
        self.excluded_dirs = ["/var/log"]

    def start(self):
        logging.info(
            f"Starting FileSystemMonitor for directories: {self.watch_directories}"
        )
        event_handler = FileSystemMonitorHandler(
            self.critical_paths, self.excluded_dirs, self.alerts
        )
        observer = Observer()
        for directory in self.watch_directories:
            observer.schedule(event_handler, path=directory, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except Exception as e:
            logging.error(f"Error in FileSystemMonitor: {e}")
            observer.stop()
        observer.join()
