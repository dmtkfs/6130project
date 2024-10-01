import time
import re
import os
import logging
import getpass  # To capture user details
import threading  # Import threading to monitor multiple logs concurrently


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.host_log_file_path = os.getenv(
            "HOST_SSH_LOG_FILE_PATH", "/var/log/auth.log"
        )
        self.container_log_file_path = os.getenv(
            "CONTAINER_SSH_LOG_FILE_PATH", "/var/log/supervisor/sshd_stdout.log"
        )
        logging.info(
            f"SSHMonitor initialized with host log file path: {self.host_log_file_path}"
        )
        logging.info(
            f"SSHMonitor initialized with container log file path: {self.container_log_file_path}"
        )

    def start(self):
        """
        Start threads for both host and container SSH log monitoring.
        """
        try:
            # Create separate threads for monitoring host and container SSH logs
            host_thread = threading.Thread(
                target=self.monitor_log_file, args=(self.host_log_file_path, "Host")
            )
            container_thread = threading.Thread(
                target=self.monitor_log_file,
                args=(self.container_log_file_path, "Container"),
            )

            # Start the threads
            host_thread.start()
            container_thread.start()

            # Ensure both threads are joined (i.e., they run concurrently)
            host_thread.join()
            container_thread.join()

        except Exception as e:
            logging.error(f"Error in SSHMonitor: {e}")

    def monitor_log_file(self, log_file_path, source):
        """
        Monitors a specific log file (host or container) for SSH activity.
        """
        if not os.path.exists(log_file_path):
            logging.error(f"SSH auth log not found at {log_file_path} ({source})")
            return

        with open(log_file_path, "r") as file:
            file.seek(0, os.SEEK_END)  # Go to the end of the log file
            while True:
                line = file.readline()
                if not line:
                    time.sleep(1)
                    continue
                self.process_line(line, source)

    def process_line(self, line, source):
        """
        Processes each line from the log file to detect SSH login attempts.
        """
        failed_login_pattern = re.compile(r"Failed password for .* from (\S+)")
        successful_login_pattern = re.compile(r"Accepted password for .* from (\S+)")
        current_user = getpass.getuser()

        failed_match = failed_login_pattern.search(line)
        if failed_match:
            ip_address = failed_match.group(1)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: {current_user} - Failed SSH login attempt from {ip_address} ({source})"
            logging.warning(message)
            for alert in self.alerts:
                alert.send_alert(f"Failed SSH Login Attempt ({source})", message)

        elif successful_login_pattern.search(line):
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: {current_user} - Successful SSH login detected ({source}): {line.strip()}"
            logging.info(message)
            for alert in self.alerts:
                alert.send_alert(f"Successful SSH Login ({source})", message)

        else:
            logging.info(f"Unrecognized log entry: {line.strip()}")
