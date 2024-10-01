# main.py

import logging
import threading
import time
from ids.config import setup_logging
from ids.alerts.email_alert import EmailAlert
from ids.alerts.log_alert import LogAlert
from ids.modules.process_monitor import ProcessMonitor
from ids.modules.ssh_monitor import SSHMonitor
from ids.modules.file_system_monitor import start_file_system_monitor
from ids.modules.container_escape_monitor import ContainerEscapeMonitor

# Initialize logging using the setup_logging function
setup_logging()
logger = logging.getLogger("Main")
logger.info("Starting IDS Application")


def run_monitor(monitor):
    try:
        monitor.start()
    except Exception as e:
        logger.critical(
            f"Monitor {monitor.__class__.__name__} encountered an error: {e}"
        )
        raise


def main():
    try:
        logger.info("IDS initialized")

        # Initialize alert mechanisms
        email_alert = EmailAlert()  # EmailAlert buffers and sends periodic emails
        log_alert = LogAlert()  # LogAlert handles real-time log alerting
        alerts = [
            log_alert,
            email_alert,
        ]  # Pass email and log alert systems to monitors

        # Initialize monitors for both container and host
        process_monitor = ProcessMonitor(alerts=alerts)
        ssh_monitor = SSHMonitor(alerts=alerts)
        container_escape_monitor = ContainerEscapeMonitor(alerts=alerts)

        # Start monitoring threads for each module
        threads = [
            threading.Thread(target=run_monitor, args=(process_monitor,), daemon=True),
            threading.Thread(target=run_monitor, args=(ssh_monitor,), daemon=True),
            threading.Thread(
                target=run_monitor, args=(container_escape_monitor,), daemon=True
            ),
        ]

        for t in threads:
            t.start()
            logger.info(f"Started monitor thread: {t.name}")

        # Start file system monitor in a separate thread
        fs_monitor_thread = threading.Thread(
            target=start_file_system_monitor,
            args=(alerts,),
            daemon=True,
            name="FileSystemMonitorThread",
        )
        fs_monitor_thread.start()
        logger.info("Started FileSystemMonitor thread")

        # Email scheduling loop
        while True:
            # Email is sent every 15 minutes containing all the buffered logs
            email_alert.send_periodic_email()
            logger.debug("Sent periodic email alert")
            time.sleep(900)  # Sleep for 15 minutes (900 seconds)

    except Exception as e:
        logger.critical(f"An unhandled exception occurred: {e}")


if __name__ == "__main__":
    main()
