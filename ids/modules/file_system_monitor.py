# ids/modules/file_system_monitor.py

from watchdog.observers.inotify import InotifyObserver
from watchdog.events import FileSystemEventHandler
import os
import logging
import threading
import time
import getpass  # To capture user details


class FileSystemEventHandlerExtended(FileSystemEventHandler):
    def __init__(self, critical_paths, excluded_dirs, alerts):
        """
        Initialize the file system event handler.

        :param critical_paths: List of critical files to monitor for changes.
        :param excluded_dirs: List of directories to exclude from monitoring.
        :param alerts: List of alert instances to notify upon detecting critical file changes.
        """
        self.alerts = alerts
        self.critical_paths = critical_paths
        self.normalized_critical_paths = [
            os.path.realpath(path) for path in critical_paths
        ]  # Normalize critical paths to ensure consistency in monitoring.
        self.excluded_dirs = [os.path.realpath(path) for path in excluded_dirs]

    def on_any_event(self, event):
        """
        Handle any file system event and check if it involves critical files.

        :param event: The file system event that occurred.
        """
        try:
            event_src_path = os.path.realpath(
                event.src_path
            )  # Normalize the event path.
            if any(
                event_src_path.startswith(excluded_dir)
                for excluded_dir in self.excluded_dirs
            ):
                return  # Ignore events in excluded directories.

            if not event.is_directory:  # Only monitor file changes.
                if (
                    event_src_path in self.normalized_critical_paths
                ):  # Check if critical files were affected.
                    if event.event_type in ("modified", "deleted", "created", "moved"):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        current_user = (
                            getpass.getuser()
                        )  # Track the user performing the action.
                        message = f"{timestamp} - User: {current_user} - Critical file {event.event_type}: {event_src_path}"
                        for alert in self.alerts:
                            alert.send_alert(
                                f"Critical File {event.event_type.title()}", message
                            )
                        logging.info(message)
        except Exception as e:
            logging.error(f"Error in file system event handling: {e}")


class FileSystemMonitor:
    def __init__(self, alerts):
        """
        Initialize the FileSystemMonitor.

        :param alerts: List of alert instances to notify upon detecting changes in critical files.
        """
        self.alerts = alerts
        self.log_file_path = os.getenv(
            "LOG_FILE_PATH", "/host_var_log/auth.log"
        )  # Log file path from environment variable.
        self.critical_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
        ]  # Critical files to monitor.
        self.watch_directories = [
            "/etc",
            "/var",
            "/home",
            "/tmp",
        ]  # Directories to watch.
        self.excluded_dirs = []  # Optionally exclude directories.
        current_user = getpass.getuser()  # Track the user who started the monitoring.
        logging.info(
            f"FileSystemMonitor initialized with log file path: {self.log_file_path} by user: {current_user}"
        )

    def start(self):
        """
        Start the file system monitoring.
        """
        try:
            logging.info(
                f"Starting FileSystemMonitor, monitoring directories: {self.watch_directories}"
            )
            event_handler = FileSystemEventHandlerExtended(
                self.critical_paths, self.excluded_dirs, self.alerts
            )
            observer = InotifyObserver()  # Create the observer for inotify events.
            for directory in self.watch_directories:
                observer.schedule(
                    event_handler, directory, recursive=True
                )  # Schedule the monitoring of directories.

            observer_thread = threading.Thread(
                target=observer.start
            )  # Run the observer in a separate thread.
            observer_thread.start()
            observer_thread.join()  # Wait for the thread to finish.
        except Exception as e:
            logging.error(f"Error in FileSystemMonitor: {e}")
