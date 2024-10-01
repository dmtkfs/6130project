import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import time
from ids.alerts.log_alert import LogAlert
from ids.alerts.email_alert import EmailAlert
from ids.config import CRITICAL_PATHS, EXCLUDED_PATHS, WHITELISTED_PROCESSES
import psutil


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

            # Log every received event for debugging purposes
            self.logger.debug(f"Received event: {event_type} on {event_src_path}")

            # Exclude events from EXCLUDED_PATHS
            if any(
                event_src_path.startswith(excl_path) for excl_path in EXCLUDED_PATHS
            ):
                self.logger.debug(
                    f"Ignored event: {event_type} on {event_src_path} as it is in excluded paths."
                )
                return

            # Monitor only specific event types (e.g., created, modified, deleted)
            if event_type not in ["created", "modified", "deleted"]:
                self.logger.debug(
                    f"Ignored event: {event_type} on {event_src_path} as it's not a critical event type."
                )
                return

            # Check if the event path is in critical paths
            if any(event_src_path.startswith(path) for path in CRITICAL_PATHS):
                # Attempt to identify the process accessing the file
                user, process_name = self.get_process_info(event_src_path)

                self.logger.debug(
                    f"Identified process: '{process_name}' by user: '{user}' accessing '{event_src_path}'"
                )

                # If the process is whitelisted, ignore
                if process_name in WHITELISTED_PROCESSES:
                    self.logger.debug(
                        f"Ignored event: {event_type} on {event_src_path} by whitelisted process '{process_name}'."
                    )
                    return

                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"User '{user}' performed '{event_type}' on '{event_src_path}' via process '{process_name}' at {event_time}"
                self.logger.info(message)

                for alert in self.alerts:
                    if isinstance(alert, LogAlert):
                        alert.send_alert("File System Event Detected", message)
                    if isinstance(alert, EmailAlert):
                        alert.buffer_log(message)
        except Exception as e:
            self.logger.error(f"Error handling file system event: {e}")

    def get_process_info(self, file_path):
        """
        Identify the process accessing the file and retrieve user information.
        """
        try:
            # Iterate over all running processes
            for proc in psutil.process_iter(["pid", "username", "name", "open_files"]):
                open_files = proc.info.get("open_files", [])
                for open_file in open_files:
                    if open_file.path == file_path:
                        return proc.info["username"], proc.info["name"]
            return "unknown_user", "unknown_process"
        except Exception as e:
            self.logger.error(f"Error retrieving process info: {e}")
            return "unknown_user", "unknown_process"


def start_file_system_monitor(alerts):
    logger = logging.getLogger("FileSystemMonitor")
    try:
        event_handler = FileSystemMonitorHandler(alerts)
        observer = Observer()

        # Monitor all critical paths
        for path in CRITICAL_PATHS:
            observer.schedule(event_handler, path=path, recursive=False)
            logger.debug(f"Scheduled monitoring on critical path: {path}")

        # Start the observer
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
