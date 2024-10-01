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

# Configure logging
logging.config.dictConfig(LOGGING_CONFIG)


def run_monitor(monitor):
    """Run the monitoring process in a separate thread."""
    try:
        monitor.start()
    except Exception as e:
        logging.critical(
            f"Monitor {monitor.__class__.__name__} encountered an error: {e}"
        )
        raise


def main():
    try:
        logging.info("IDS initialized")

        # Initialize alert mechanisms
        email_alert = EmailAlert()  # EmailAlert buffers and sends periodic emails
        log_alert = LogAlert()  # LogAlert handles real-time logging

        # Pass the alert systems to the monitors
        alerts = [log_alert, email_alert]

        # Initialize monitors for both container and host
        process_monitor = ProcessMonitor(alerts=alerts)
        ssh_monitor = SSHMonitor(
            log_alert=log_alert, email_alert=email_alert
        )  # Separate log and email alerts
        container_escape_monitor = ContainerEscapeMonitor(alerts=alerts)

        # Start monitoring threads for each module
        threads = [
            threading.Thread(target=run_monitor, args=(process_monitor,), daemon=True),
            threading.Thread(target=run_monitor, args=(ssh_monitor,), daemon=True),
            threading.Thread(
                target=run_monitor, args=(container_escape_monitor,), daemon=True
            ),
        ]

        # Start all threads
        for t in threads:
            t.start()

        # Start file system monitor in the main thread (it monitors both container and host)
        start_file_system_monitor(alerts=alerts)

        # Email scheduling loop
        while True:
            # Send aggregated emails every 15 minutes
            email_alert.send_periodic_email()
            time.sleep(900)  # Sleep for 15 minutes (900 seconds)

    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}")


if __name__ == "__main__":
    main()
