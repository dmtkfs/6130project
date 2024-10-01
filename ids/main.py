import logging
import logging.config
import threading
import time
from ids.alerts.email_alert import EmailAlert
from ids.alerts.log_alert import LogAlert
from ids.modules.process_monitor import ProcessMonitor
from ids.modules.ssh_monitor import SSHMonitor
from ids.modules.file_system_monitor import start_file_system_monitor
from ids.modules.container_escape_monitor import ContainerEscapeMonitor
from ids.config import LOGGING_CONFIG

# Configure logging using dictConfig
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
        logging.info(f"IDS initialized")

        # Initialize alert mechanisms
        alerts = [
            EmailAlert(),  # Remove rate_limit, rate_period, aggregate_interval
            LogAlert(),
        ]

        # Initialize monitors
        process_monitor = ProcessMonitor(alerts=alerts)
        ssh_monitor = SSHMonitor(alerts=alerts)
        container_escape_monitor = ContainerEscapeMonitor(alerts=alerts)

        # Start monitoring threads
        threads = []
        threads.append(
            threading.Thread(target=run_monitor, args=(process_monitor,), daemon=True)
        )
        threads.append(
            threading.Thread(target=run_monitor, args=(ssh_monitor,), daemon=True)
        )
        threads.append(
            threading.Thread(
                target=run_monitor, args=(container_escape_monitor,), daemon=True
            )
        )

        for t in threads:
            t.start()

        # Start file system monitor in the main thread
        start_file_system_monitor(alerts=alerts)

        # Keep the main thread alive
        for t in threads:
            t.join()

    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}")


if __name__ == "__main__":
    main()
