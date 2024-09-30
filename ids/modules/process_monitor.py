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

        # Retrieve the log file path from environment variable or use default
        self.log_file_path = os.getenv("LOG_FILE_PATH", "/host_var_log/auth.log")

        logging.info(
            f"ProcessMonitor initialized with log file path: {self.log_file_path}"
        )

        # Define important processes to filter (you can adjust this list)
        self.important_processes = ["sshd", "bash", "python", "docker", "containerd"]

    def start(self):
        """
        Start monitoring processes.
        """
        logging.info("ProcessMonitor started.")
        # Initialize known_pids with current processes
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
                            if proc.name() not in self.important_processes:
                                continue  # Ignore unimportant processes

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

                            # Trigger alerts only for important processes
                            for alert in self.alerts:
                                alert.send_alert("New Process Detected", process_info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            logging.warning(f"Failed to access process PID={pid}: {e}")
                self.known_pids = current_pids
                time.sleep(self.poll_interval)
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")
