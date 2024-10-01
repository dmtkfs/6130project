import logging
import psutil
from datetime import datetime
import time


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("ContainerEscapeMonitor initialized.")

    def get_process_info(self, pid):
        try:
            process = psutil.Process(pid)
            return process.username(), process.cmdline()
        except Exception as e:
            logging.error(f"Failed to retrieve process info for PID {pid}: {e}")
            return None, None

    def start(self):
        logging.info("ContainerEscapeMonitor started.")
        while True:
            pid = 100  # Example PID, replace with detection logic
            user, cmdline = self.get_process_info(pid)

            if user and cmdline:
                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"{event_time} - Potential container escape attempt detected by {user} (Cmdline: {' '.join(cmdline)})"
                logging.critical(message)  # Log as CRITICAL

                # Buffer the log for email later
                for alert in self.alerts:
                    if hasattr(alert, "buffer_log"):
                        alert.buffer_log(message)

            time.sleep(5)  # Adjust this as needed
