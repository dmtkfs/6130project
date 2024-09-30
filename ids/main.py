import logging
import logging.config
import threading
import time
from ids.alerts.email_alert import EmailAlert
from ids.alerts.log_alert import LogAlert
from ids.modules.process_monitor import ProcessMonitor
from ids.modules.ssh_monitor import SSHMonitor
from ids.modules.file_system_monitor import FileSystemMonitor
from ids.modules.container_escape_monitor import ContainerEscapeMonitor
from ids.config import LOGGING_CONFIG
import getpass  # To capture user details
import sys  # To handle system exit

# Configure logging using dictConfig
logging.config.dictConfig(LOGGING_CONFIG)


def run_monitor(monitor):
    """
    Wrapper to run monitor's start method with exception handling.
    """
    try:
        monitor.start()
    except Exception as e:
        logging.critical(
            f"Monitor {monitor.__class__.__name__} encountered an error: {e}"
        )
        # Optionally, re-raise to terminate the main process
        raise


def main():
    try:
        # Capture the username who is running the IDS
        current_user = getpass.getuser()
        start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f"IDS initialized at {start_time} by user: {current_user}")

        # Initialize alert mechanisms
        alerts = [EmailAlert(), LogAlert()]

        # Initialize monitors
        process_monitor = ProcessMonitor(alerts=alerts)
        ssh_monitor = SSHMonitor(alerts=alerts)
        file_system_monitor = FileSystemMonitor(alerts=alerts)
        container_escape_monitor = ContainerEscapeMonitor(alerts=alerts)

        # Start monitoring threads with exception handling
        threads = []

        t_process_monitor = threading.Thread(
            target=run_monitor, args=(process_monitor,)
        )
        t_process_monitor.start()
        threads.append(t_process_monitor)

        t_ssh_monitor = threading.Thread(target=run_monitor, args=(ssh_monitor,))
        t_ssh_monitor.start()
        threads.append(t_ssh_monitor)

        t_file_system_monitor = threading.Thread(
            target=run_monitor, args=(file_system_monitor,)
        )
        t_file_system_monitor.start()
        threads.append(t_file_system_monitor)

        t_container_escape_monitor = threading.Thread(
            target=run_monitor, args=(container_escape_monitor,)
        )
        t_container_escape_monitor.start()
        threads.append(t_container_escape_monitor)

        logging.info(
            f"All monitoring services started at {start_time} by user: {current_user}"
        )

        for t in threads:
            t.join()
    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
