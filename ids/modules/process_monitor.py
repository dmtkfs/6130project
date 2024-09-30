import psutil
import time
import logging
import os
import getpass  # To capture user details


class ProcessMonitor:
    def __init__(self, alerts, poll_interval=5):
        """
        Initialize the ProcessMonitor.
        :param alerts: List of alert instances to notify upon detecting a new process.
        :param poll_interval: Time interval (in seconds) between process scans.
        """
        self.alerts = alerts
        self.poll_interval = poll_interval
        self.known_pids = set()
        self.log_file_path = os.getenv(
            "LOG_FILE_PATH", "/var/log/ids_app/ids.log"
        )  # Updated
        logging.info(
            f"ProcessMonitor initialized with log file path: {self.log_file_path}"
        )

    def start(self):
        """
        Start monitoring processes.
        """
        logging.info("ProcessMonitor started.")
        self.known_pids = set(psutil.pids())
        logging.debug(f"Initial PIDs: {self.known_pids}")

        try:
            while True:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self.known_pids
                if new_pids:
                    for pid in new_pids:
                        try:
                            proc = psutil.Process(pid)
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            current_user = (
                                getpass.getuser()
                            )  # Track the user performing the action
                            process_info = (
                                f"{timestamp} - User: {current_user} - New process detected: "
                                f"PID={proc.pid}, Name={proc.name()}, "
                                f"Cmdline={' '.join(proc.cmdline())}"
                            )
                            logging.info(process_info)
                            for alert in self.alerts:
                                alert.send_alert("New Process Detected", process_info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            logging.warning(f"Failed to access process PID={pid}: {e}")
                self.known_pids = current_pids
                time.sleep(self.poll_interval)
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")
