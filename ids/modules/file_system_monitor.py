import os
import logging
import time
import psutil  # For retrieving process details by PID
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("FileSystemMonitorHandler initialized.")

    def get_process_info(self, pid):
        """Get process information from PID."""
        try:
            process = psutil.Process(pid)
            return process.username(), process.cmdline()
        except Exception as e:
            logging.error(f"Failed to retrieve process info for PID {pid}: {e}")
            return None, None

    def on_any_event(self, event):
        event_type = event.event_type
        event_src_path = event.src_path
        pid = os.getpid()  # Get the PID of the process that triggered the event
        user, cmdline = self.get_process_info(pid)

        message = f"Detected event: {event_type} on {event_src_path} by {user} (Cmdline: {' '.join(cmdline)})"

        logging.info(message)
        for alert in self.alerts:
            alert.send_alert("File System Event Detected", message)


def start_file_system_monitor(alerts):
    event_handler = FileSystemMonitorHandler(alerts)
    observer = Observer()
    observer.schedule(event_handler, path="/etc", recursive=True)
    observer.start()
    logging.info("FileSystemMonitor started.")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
