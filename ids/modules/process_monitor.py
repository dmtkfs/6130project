import psutil
import time
import logging


class ProcessMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        logging.info("ProcessMonitor initialized.")

    def start(self):
        logging.info("ProcessMonitor started.")
        try:
            while True:
                self.monitor_processes()
                time.sleep(5)  # Adjust based on system needs
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")

    def monitor_processes(self):
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
            process_info = f"PID={proc.info['pid']}, Name={proc.info['name']}, User={proc.info['username']}, Cmdline={' '.join(proc.info['cmdline'])}"
            logging.info(f"New process detected: {process_info}")

            # Example suspicious process detection
            if proc.info["username"] == "root":
                alert_message = f"Suspicious root process detected: {process_info}"
                for alert in self.alerts:
                    alert.send_alert("Suspicious Process Detected", alert_message)
