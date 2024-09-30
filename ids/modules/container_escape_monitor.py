import logging
import os
import time
import getpass  # To capture user details
import subprocess


class ContainerEscapeMonitor:
    def __init__(self, alerts):
        """
        Initialize the ContainerEscapeMonitor class with the log file path
        and a list of alerts to send in case of a container escape attempt.
        """
        self.log_file_path = os.getenv(
            "CONTAINER_LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )
        self.alerts = alerts
        self.sensitive_paths = [
            "/host_root",
            "/proc/host",
        ]  # Add paths that should not be accessible
        self.sudo_command_log = []  # Keep track of any sudo commands
        current_user = getpass.getuser()
        logging.info(f"ContainerEscapeMonitor initialized by user: {current_user}")

    def start(self):
        """
        Start monitoring the container for escape attempts or unauthorized actions.
        """
        logging.info("Starting ContainerEscapeMonitor")

        while True:
            self.monitor_sudo_attempts()
            self.check_sensitive_paths()
            time.sleep(5)  # Adjust the polling interval as needed

    def check_sensitive_paths(self):
        """
        Check if any unauthorized access to sensitive paths is happening.
        """
        try:
            for path in self.sensitive_paths:
                if os.path.exists(path):
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    current_user = getpass.getuser()
                    message = f"{timestamp} - User: {current_user} - Potential container escape attempt detected: Accessed {path}"
                    logging.warning(message)
                    for alert in self.alerts:
                        alert.send_alert("Container Escape Attempt Detected", message)
        except Exception as e:
            logging.error(f"Error checking sensitive paths: {e}")

    def monitor_sudo_attempts(self):
        """
        Monitor if the 'sudo' command is used inside the container.
        """
        try:
            # Run 'sudo' related command to detect privilege escalation attempts
            result = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True)
            if "sudo" in result.stdout and result.stdout not in self.sudo_command_log:
                self.sudo_command_log.append(result.stdout)
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                current_user = getpass.getuser()
                message = f"{timestamp} - User: {current_user} - Sudo command detected. Potential container escape attempt: {result.stdout}"
                logging.warning(message)
                for alert in self.alerts:
                    alert.send_alert("Container Escape Attempt Detected", message)
        except Exception as e:
            logging.error(f"Error monitoring sudo commands: {e}")
