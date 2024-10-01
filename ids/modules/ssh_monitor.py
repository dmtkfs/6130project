import time
import logging


class SSHMonitor:
    def __init__(self, alerts):
        self.alerts = alerts
        self.log_file_positions = {}
        logging.info("SSHMonitor initialized.")

    def start(self):
        logging.info("SSHMonitor started.")
        try:
            while True:
                self.monitor_ssh_logs()
                time.sleep(5)
        except Exception as e:
            logging.error(f"SSHMonitor encountered an error: {e}")

    def monitor_ssh_logs(self):
        log_files = [
            ("/var/log/auth.log", "Host"),
            ("/var/log/supervisor/sshd_stdout.log", "Container"),
        ]
        for log_file, source in log_files:
            try:
                with open(log_file, "r") as f:
                    for line in f:
                        if "Accepted" in line or "Failed" in line:
                            message = (
                                f"SSH activity detected in {source}: {line.strip()}"
                            )
                            for alert in self.alerts:
                                alert.send_alert(
                                    f"SSH Activity Detected ({source})", message
                                )
            except Exception as e:
                logging.error(f"Error reading {source} SSH logs: {e}")
