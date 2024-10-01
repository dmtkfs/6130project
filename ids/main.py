import logging
import logging.config
import threading
import time
import sys
from ids.alerts.email_alert import EmailAlert
from ids.alerts.log_alert import LogAlert
from ids.modules.process_monitor import ProcessMonitor
from ids.modules.ssh_monitor import SSHMonitor
from ids.modules.file_system_monitor import start_file_system_monitor
from ids.modules.container_escape_monitor import ContainerEscapeMonitor
from ids.config import LOGGING_CONFIG, CRITICAL_PATHS, EXCLUDED_DIRS

# Configure logging
logging.config.dictConfig(LOGGING_CONFIG)


def run_monitor(monitor):
    try:
        monitor.start()
    except Exception as e:
        logging.critical(
            f"Monitor {monitor.__class__.__name__} encountered an error: {e}"
        )
        raise


def main():
    try:
        start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f"IDS initialized at {start_time}")

        # Initialize alert mechanisms
        alerts = [
            EmailAlert(rate_limit=5, rate_period=300, aggregate_interval=600),
            LogAlert(),
        ]

        # Initialize monitors
        process_monitor = ProcessMonitor(alerts=alerts)
        ssh_monitor = SSHMonitor(alerts=alerts)
        file_system_monitor_thread = threading.Thread(
            target=start_file_system_monitor,
            args=(CRITICAL_PATHS, EXCLUDED_DIRS, alerts),
            daemon=True,
        )
        container_escape_monitor = ContainerEscapeMonitor(alerts=alerts)

        # Start monitoring threads
        threads = []

        t_process_monitor = threading.Thread(
            target=run_monitor, args=(process_monitor,), daemon=True
        )
        t_process_monitor.start()
        threads.append(t_process_monitor)

        t_ssh_monitor = threading.Thread(
            target=run_monitor, args=(ssh_monitor,), daemon=True
        )
        t_ssh_monitor.start()
        threads.append(t_ssh_monitor)

        file_system_monitor_thread.start()
        threads.append(file_system_monitor_thread)

        t_container_escape_monitor = threading.Thread(
            target=run_monitor, args=(container_escape_monitor,), daemon=True
        )
        t_container_escape_monitor.start()
        threads.append(t_container_escape_monitor)

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
