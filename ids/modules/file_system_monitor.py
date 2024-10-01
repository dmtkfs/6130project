import logging
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime


class FileSystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("FileSystemMonitorHandler initialized.")

    def on_any_event(self, event):
        event_type = event.event_type
        event_src_path = event.src_path
        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"{event_time} - Detected event: {event_type} on {event_src_path}"
        logging.info(message)

        # Buffer the log for email later
        for alert in self.alerts:
            if hasattr(alert, "buffer_log"):
                alert.buffer_log(message)


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
