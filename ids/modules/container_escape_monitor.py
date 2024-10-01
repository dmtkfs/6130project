import logging
import psutil  # To fetch process details
from datetime import datetime


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("ContainerEscapeMonitor initialized.")

    def get_process_info(self, pid):
        """Get process information from PID."""
        try:
            process = psutil.Process(pid)
            return process.username(), process.cmdline()
        except Exception as e:
            logging.error(f"Failed to retrieve process info for PID {pid}: {e}")
            return None, None

    def start(self):
        logging.info("ContainerEscapeMonitor started.")
        while True:
            # Simulating a container escape detection mechanism (replace with real check)
            # Here, you should implement the actual detection logic
            pid = 100  # This is an example PID (replace with real detection PID)
            user, cmdline = self.get_process_info(pid)

            if user and cmdline:
                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = f"{event_time} - Potential container escape attempt detected by {user} (Cmdline: {' '.join(cmdline)})"
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert("Container Escape Attempt Detected", message)

            time.sleep(5)  # Monitor continuously (adjust this sleep time as needed)
