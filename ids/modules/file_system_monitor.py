# ids/modules/file_system_monitor.py

from watchdog.observers.inotify import InotifyObserver
from watchdog.events import FileSystemEventHandler
import os
import logging
import threading

class FileSystemEventHandlerExtended(FileSystemEventHandler):
    def __init__(self, critical_paths, excluded_dirs, alerts):
        self.alerts = alerts
        self.critical_paths = critical_paths
        self.normalized_critical_paths = [os.path.realpath(path) for path in critical_paths]
        self.excluded_dirs = [os.path.realpath(path) for path in excluded_dirs]

    def on_any_event(self, event):
        try:
            event_src_path = os.path.realpath(event.src_path)
            if any(event_src_path.startswith(excluded_dir) for excluded_dir in self.excluded_dirs):
                return
            if not event.is_directory:
                if event_src_path in self.normalized_critical_paths:
                    if event.event_type in ('modified', 'deleted', 'created', 'moved'):
                        message = f"Critical file {event.event_type}: {event_src_path}"
                        for alert in self.alerts:
                            alert.send_alert(f"Critical File {event.event_type.title()}", message)
        except Exception as e:
            logging.error(f"Error in file system event handling: {e}")

class FileSystemMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.critical_paths = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/group']
        self.watch_directories = ['/etc', '/var', '/home', '/tmp']
        self.excluded_dirs = []

    def start(self):
        try:
            event_handler = FileSystemEventHandlerExtended(self.critical_paths, self.excluded_dirs, self.alerts)
            observer = InotifyObserver()
            for directory in self.watch_directories:
                observer.schedule(event_handler, directory, recursive=True)
            observer_thread = threading.Thread(target=observer.start)
            observer_thread.start()
            observer_thread.join()
        except Exception as e:
            logging.error(f"Error in FileSystemMonitor: {e}")
