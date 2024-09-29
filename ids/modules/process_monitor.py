# ids/modules/process_monitor.py

import psutil
import time
import logging

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
                            process_info = f"New process detected: PID={proc.pid}, Name={proc.name()}, Cmdline={' '.join(proc.cmdline())}"
                            logging.info(process_info)
                            # Trigger alerts
                            for alert in self.alerts:
                                alert.send_alert("New Process Detected", process_info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            logging.warning(f"Failed to access process PID={pid}: {e}")
                self.known_pids = current_pids
                time.sleep(self.poll_interval)
        except Exception as e:
            logging.error(f"ProcessMonitor encountered an error: {e}")
