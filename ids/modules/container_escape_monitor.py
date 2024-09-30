# ids/modules/container_escape_monitor.py

import logging
import os
import time
import getpass


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.sensitive_paths = ["/host_root", "/proc/host", "/etc", "/var/log"]
        logging.info("ContainerEscapeMonitor initialized")

    def start(self):
        try:
            while True:
                for path in self.sensitive_paths:
                    if os.path.exists(path):
                        try:
                            if os.access(path, os.R_OK):
                                logging.info(f"Accessed sensitive path: {path}")
                            else:
                                logging.warning(
                                    f"Access attempt denied for sensitive path: {path}"
                                )
                        except Exception as e:
                            logging.error(f"Error accessing sensitive path: {e}")
                time.sleep(5)
        except Exception as e:
            logging.error(f"Error in ContainerEscapeMonitor: {e}")
