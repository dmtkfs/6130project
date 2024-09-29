# ids/modules/container_escape_monitor.py

import os
import time
import logging

class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.sensitive_paths = ['/host_root', '/proc/host']

    def start(self):
        try:
            while True:
                time.sleep(5)
                for path in self.sensitive_paths:
                    if os.path.exists(path):
                        message = f"Potential container escape attempt detected: Accessed {path}"
                        for alert in self.alerts:
                            alert.send_alert("Container Escape Attempt", message)
        except Exception as e:
            logging.error(f"Error in ContainerEscapeMonitor: {e}")
