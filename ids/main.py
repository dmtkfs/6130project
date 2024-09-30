# ids/main.py

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

# Configure logging using dictConfig
logging.config.dictConfig(LOGGING_CONFIG)


def main():
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

    # Start monitoring threads
    threads = []

    t_process_monitor = threading.Thread(target=process_monitor.start)
    t_process_monitor.start()
    threads.append(t_process_monitor)

    t_ssh_monitor = threading.Thread(target=ssh_monitor.start)
    t_ssh_monitor.start()
    threads.append(t_ssh_monitor)

    t_file_system_monitor = threading.Thread(target=file_system_monitor.start)
    t_file_system_monitor.start()
    threads.append(t_file_system_monitor)

    t_container_escape_monitor = threading.Thread(target=container_escape_monitor.start)
    t_container_escape_monitor.start()
    threads.append(t_container_escape_monitor)

    logging.info(
        f"All monitoring services started at {start_time} by user: {current_user}"
    )

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
