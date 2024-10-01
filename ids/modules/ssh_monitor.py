# ids/modules/ssh_monitor.py

import logging
import time
import re
import os
from threading import Thread


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.host_log_file_path = os.getenv(
            "HOST_SSH_LOG_FILE_PATH", "/host_var_log/auth.log"
        )
        self.container_ssh_log_file_path = os.getenv(
            "CONTAINER_SSH_LOG_FILE_PATH", "/var/log/supervisor/sshd_stdout.log"
        )
        logging.debug(
            f"SSHMonitor initialized with host log: {self.host_log_file_path} and container log: {self.container_ssh_log_file_path}"
        )

    def start(self):
        host_thread = Thread(
            target=self.monitor_log_file,
            args=(self.host_log_file_path, "Host"),
            daemon=True,
        )
        container_thread = Thread(
            target=self.monitor_log_file,
            args=(self.container_ssh_log_file_path, "Container"),
            daemon=True,
        )
        host_thread.start()
        container_thread.start()
        logging.info("SSHMonitor started.")
        host_thread.join()
        container_thread.join()

    def monitor_log_file(self, log_file_path, source):
        if not os.path.exists(log_file_path):
            logging.error(f"SSH auth log not found at {log_file_path} ({source})")
            return

        logging.debug(f"Monitoring SSH log at {log_file_path} ({source})")
        with open(log_file_path, "r") as file:
            file.seek(0, os.SEEK_END)  # Go to the end of the log file
            while True:
                line = file.readline()
                if not line:
                    time.sleep(1)
                    continue
                self.process_line(line, source)

    def process_line(self, line, source):
        failed_login_pattern = re.compile(r"Failed password for .* from (\S+)")
        successful_login_pattern = re.compile(r"Accepted password for .* from (\S+)")
        connection_closed_pattern = re.compile(
            r"Connection closed by authenticating user (\S+) (\S+) port (\d+) \[preauth\]"
        )

        failed_match = failed_login_pattern.search(line)
        successful_match = successful_login_pattern.search(line)
        connection_closed_match = connection_closed_pattern.search(line)

        if failed_match:
            ip_address = failed_match.group(1)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: ids_user - Failed SSH login attempt from {ip_address} ({source})"
            logging.warning(message)
            for alert in self.alerts:
                alert.send_alert(f"Failed SSH Login Attempt ({source})", message)

        elif successful_match:
            ip_address = successful_match.group(1)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: ids_user - Successful SSH login detected ({source}): {line.strip()}"
            logging.info(message)
            for alert in self.alerts:
                alert.send_alert(f"Successful SSH Login ({source})", message)

        elif connection_closed_match:
            user = connection_closed_match.group(1)
            ip = connection_closed_match.group(2)
            port = connection_closed_match.group(3)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"{timestamp} - User: ids_user - SSH connection closed for user {user} from {ip} port {port} ({source})"
            logging.info(message)
            # Optionally, send an alert for connection closures
            # for alert in self.alerts:
            #     alert.send_alert(f"SSH Connection Closed ({source})", message)

        else:
            logging.debug(f"Unrecognized SSH log entry: {line.strip()}")
