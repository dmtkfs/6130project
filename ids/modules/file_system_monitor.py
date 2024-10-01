import logging
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("FileSystemMonitorHandler initialized.")

    def on_any_event(self, event):
        event_type = event.event_type
        event_src_path = event.src_path
        message = f"Detected event: {event_type} on {event_src_path}"
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
