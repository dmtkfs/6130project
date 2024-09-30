from watchdog.observers.inotify import InotifyObserver
from watchdog.events import FileSystemEventHandler
import os
import logging
import threading
import time
import getpass  # To capture user details


class FileSystemEventHandlerExtended(FileSystemEventHandler):
    def __init__(self, critical_paths, excluded_dirs, alerts, log_source):
        self.alerts = alerts
        self.critical_paths = critical_paths
        self.normalized_critical_paths = [
            os.path.realpath(path) for path in critical_paths
        ]
        self.excluded_dirs = [os.path.realpath(path) for path in excluded_dirs]
        self.log_source = log_source  # Track whether the log is from host or container

    def on_any_event(self, event):
        try:
            event_src_path = os.path.realpath(event.src_path)
            if any(
                event_src_path.startswith(excluded_dir)
                for excluded_dir in self.excluded_dirs
            ):
                return
            if not event.is_directory:
                if event_src_path in self.normalized_critical_paths:
                    if event.event_type in ("modified", "deleted", "created", "moved"):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        current_user = (
                            getpass.getuser()
                        )  # Track the user performing the action
                        message = (
                            f"{timestamp} - User: {current_user} - Log Source: {self.log_source} "
                            f"- Critical file {event.event_type}: {event_src_path}"
                        )
                        for alert in self.alerts:
                            alert.send_alert(
                                f"Critical File {event.event_type.title()}", message
                            )
                        logging.info(message)
        except Exception as e:
            logging.error(f"Error in file system event handling: {e}")


class FileSystemMonitor:
    def __init__(self, alerts, log_source, watch_directories=None):
        self.alerts = alerts
        self.log_source = log_source  # Track log source (host or container)
        self.log_file_path = os.getenv(
            "LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )  # Log file path from environment variable

        # Critical paths to watch
        self.critical_paths = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group"]
        # Directories to monitor
        self.watch_directories = (
            watch_directories
            if watch_directories is not None
            else ["/etc", "/var", "/home", "/tmp"]
        )
        self.excluded_dirs = []
        current_user = getpass.getuser()
        logging.info(
            f"FileSystemMonitor initialized for {self.log_source} with log file path: {self.log_file_path} by user: {current_user}"
        )

    def start(self):
        try:
            logging.info(
                f"Starting FileSystemMonitor for {self.log_source}, monitoring directories: {self.watch_directories}"
            )
            event_handler = FileSystemEventHandlerExtended(
                self.critical_paths, self.excluded_dirs, self.alerts, self.log_source
            )
            observer = InotifyObserver()
            for directory in self.watch_directories:
                observer.schedule(event_handler, directory, recursive=True)
            observer_thread = threading.Thread(target=observer.start)
            observer_thread.start()
            observer_thread.join()
        except Exception as e:
            logging.error(f"Error in FileSystemMonitor: {e}")
