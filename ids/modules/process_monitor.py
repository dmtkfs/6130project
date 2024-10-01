import psutil
import logging
import time
from datetime import datetime

# Adjust paths if necessary
HOST_PROCESS_LOG_FILE_PATH = (
    "/host_var_log/syslog"  # Host's syslog path for process monitoring
)
CONTAINER_PROCESS_LOG_FILE_PATH = "/proc"  # Container's process monitoring path


class ProcessMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.existing_pids = set()  # Track running processes
        logging.info("ProcessMonitor initialized.")

    def start(self):
        logging.info("ProcessMonitor started.")
        try:
            while True:
                self.check_new_processes()
                time.sleep(5)  # Adjust the sleep time based on your needs
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")

    def check_new_processes(self):
        # Monitor container processes
        self.monitor_processes_in_container()

        # Monitor host processes (using the mounted syslog)
        self.monitor_processes_on_host()

    def monitor_processes_in_container(self):
        current_pids = set(psutil.pids())
        new_pids = current_pids - self.existing_pids
        self.existing_pids = current_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_info = f"PID={pid}, Name={proc.name()}, User={proc.username()}, Cmdline={' '.join(proc.cmdline())}"
                event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.critical(
                    f"Suspicious Process Detected in Container - {event_time} - {proc_info}"
                )
                for alert in self.alerts:
                    alert.send_alert(
                        "Suspicious Process Detected in Container",
                        f"{event_time} - {proc_info}",
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def monitor_processes_on_host(self):
        try:
            with open(HOST_PROCESS_LOG_FILE_PATH, "r") as log_file:
                for line in log_file:
                    if (
                        "new process" in line.lower()
                    ):  # Adjust keyword based on actual log format
                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        logging.critical(
                            f"Suspicious Process Detected on Host - {event_time} - {line.strip()}"
                        )
                        for alert in self.alerts:
                            alert.send_alert(
                                "Suspicious Process Detected on Host",
                                f"{event_time} - {line.strip()}",
                            )
        except Exception as e:
            logging.error(f"Error reading host process log: {e}")
