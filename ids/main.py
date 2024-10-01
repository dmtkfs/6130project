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
<<<<<<< HEAD
from ids.config import LOGGING_CONFIG
=======
from ids.config import LOGGING_CONFIG, CRITICAL_PATHS, EXCLUDED_DIRS
>>>>>>> 154415a767f2f928ab03a07112e280b674186eb0

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
            EmailAlert(rate_limit=5, rate_period=300, aggregate_interval=600),
            LogAlert(),
        ]

        # Initialize monitors
        process_monitor = ProcessMonitor(alerts=alerts)
        ssh_monitor = SSHMonitor(alerts=alerts)
<<<<<<< HEAD
=======
        file_system_monitor_thread = threading.Thread(
            target=start_file_system_monitor,
            args=(CRITICAL_PATHS, EXCLUDED_DIRS, alerts),
            daemon=True,
        )
>>>>>>> 154415a767f2f928ab03a07112e280b674186eb0
        container_escape_monitor = ContainerEscapeMonitor(alerts=alerts)

        # Start monitoring threads
        threads = []
        threads.append(
            threading.Thread(target=run_monitor, args=(process_monitor,), daemon=True)
        )
        threads.append(
            threading.Thread(target=run_monitor, args=(ssh_monitor,), daemon=True)
        )
<<<<<<< HEAD
        threads.append(
            threading.Thread(
                target=run_monitor, args=(container_escape_monitor,), daemon=True
            )
        )
=======
        t_ssh_monitor.start()
        threads.append(t_ssh_monitor)

        file_system_monitor_thread.start()
        threads.append(file_system_monitor_thread)
>>>>>>> 154415a767f2f928ab03a07112e280b674186eb0

        for t in threads:
            t.start()

<<<<<<< HEAD
        # Start file system monitor in the main thread
        start_file_system_monitor(alerts=alerts)

        # Keep the main thread alive
        for t in threads:
            t.join()
=======
        # Keep the main thread alive
        while True:
            time.sleep(1)
>>>>>>> 154415a767f2f928ab03a07112e280b674186eb0

    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}")


if __name__ == "__main__":
    main()
