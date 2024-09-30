import logging
import os
import time
import psutil  # To monitor processes
import getpass


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.host_log_file_path = os.getenv(
            "HOST_LOG_FILE_PATH", "/var/log/auth.log"
        )  # Path to host logs
        self.container_log_file_path = os.getenv(
            "CONTAINER_LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )  # Path to container logs
        self.monitored_commands = [
            "docker",
            "nsenter",
            "chroot",
        ]  # Commands that indicate escape attempts
        logging.info(f"ContainerEscapeMonitor initialized.")

    def start(self):
        logging.info("Starting ContainerEscapeMonitor")
        self.monitor_processes()

    def monitor_processes(self):
        """
        Monitor container processes for escape attempts based on privileged commands.
        """
        logging.info("Monitoring processes for potential container escape attempts.")
        try:
            while True:
                for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        cmdline = " ".join(proc.info["cmdline"])
                        if any(
                            command in cmdline for command in self.monitored_commands
                        ):
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            current_user = getpass.getuser()
                            message = f"{timestamp} - User: {current_user} - Container escape attempt detected: {cmdline}"
                            logging.warning(message)
                            # Send an alert
                            for alert in self.alerts:
                                alert.send_alert(
                                    "Container Escape Attempt Detected", message
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                time.sleep(1)  # Check every second
        except Exception as e:
            logging.error(f"Error in monitoring processes: {e}")
