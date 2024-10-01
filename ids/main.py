import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import time
import os
import threading
import sys
from subprocess import Popen, PIPE
import re
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set to DEBUG for detailed output
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)


def monitor_processes():
    """
    Monitors running processes for suspicious activity.
    """
    try:
        logging.info("Process monitoring started.")
        SENSITIVE_BINARIES = ["/usr/bin/docker", "/usr/bin/runc"]
        WHITELISTED_PROCESSES = [
            "supervisord",
            "python",
            "python3",
            "tail",
            "sh",
            "sshd",
            "ids.py",
        ]

        while True:
            try:
                for proc in psutil.process_iter(
                    ["pid", "name", "username", "exe", "cmdline", "uids"]
                ):
                    process_name = proc.info.get("name")
                    process_info = f"Process: {process_name} (PID: {proc.info['pid']}, User: {proc.info.get('username')}, CMD: {' '.join(proc.info.get('cmdline') or [])})"

                    # Detect processes running as root that are not whitelisted
                    if (
                        proc.info.get("username") == "root"
                        and proc.info["pid"] != 1
                        and process_name not in WHITELISTED_PROCESSES
                    ):
                        alert_message = (
                            f"Suspicious root process detected: {process_info}"
                        )
                        logging.warning(alert_message)

                    # Detect execution of sensitive binaries
                    exe = proc.info.get("exe") or ""
                    if exe in SENSITIVE_BINARIES:
                        alert_message = (
                            f"Sensitive binary execution detected: {process_info}"
                        )
                        logging.warning(alert_message)

                    # Detect privilege escalation
                    uids = proc.info.get("uids")
                    if uids and uids.real != uids.effective:
                        alert_message = f"Privilege escalation detected: {process_info}"
                        logging.warning(alert_message)

                time.sleep(5)
            except Exception as e:
                logging.error(f"Error in process monitoring loop: {e}")
                time.sleep(5)
    except Exception as e:
        logging.error(f"Critical error in monitor_processes: {e}")


def monitor_process_creations():
    """
    Monitors for new process creations.
    """
    try:
        logging.info("Process creation monitoring started.")
        existing_pids = set(psutil.pids())

        while True:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - existing_pids
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                        cmdline = " ".join(proc.cmdline())
                        process_info = f"New process created: {process_name} (PID: {pid}, CMD: {cmdline})"
                        if process_name != "ids.py":
                            logging.info(process_info)
                    except psutil.NoSuchProcess:
                        continue
                    except Exception as e:
                        logging.error(f"Error accessing process {pid}: {e}")
                existing_pids = current_pids
                time.sleep(1)
            except Exception as e:
                logging.error(f"Error in process creation monitoring loop: {e}")
                time.sleep(1)
    except Exception as e:
        logging.error(f"Critical error in monitor_process_creations: {e}")


class FileMonitorHandler(FileSystemEventHandler):
    """
    Monitors file system events.
    """

    def __init__(self):
        super().__init__()
        self.excluded_dirs = ["/var/log", "/ids_app/logs"]
        self.critical_paths = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group"]
        self.normalized_critical_paths = [
            os.path.realpath(path) for path in self.critical_paths
        ]

    def on_any_event(self, event):
        try:
            event_src_path = os.path.realpath(event.src_path)

            if any(
                event_src_path.startswith(os.path.realpath(excluded_dir))
                for excluded_dir in self.excluded_dirs
            ):
                return

            if not event.is_directory:
                if event_src_path in self.normalized_critical_paths:
                    if event.event_type in ("modified", "deleted", "created", "moved"):
                        alert_message = (
                            f"Critical file {event.event_type}: {event_src_path}"
                        )
                        logging.warning(alert_message)
        except Exception as e:
            logging.error(f"Error in file system event handling: {e}")


def monitor_files(paths_to_watch):
    """
    Sets up file system monitoring on specified paths.
    """
    try:
        logging.info(f"Starting file monitoring on: {', '.join(paths_to_watch)}")
        event_handler = FileMonitorHandler()
        observer = Observer()
        for path in paths_to_watch:
            if os.path.exists(path):
                observer.schedule(event_handler, path=path, recursive=True)
            else:
                logging.warning(f"Path does not exist and will be skipped: {path}")
        observer.start()
        try:
            while True:
                time.sleep(1)
        except Exception as e:
            logging.error(f"Error in file monitoring loop: {e}")
        finally:
            observer.stop()
            observer.join()
    except Exception as e:
        logging.error(f"Critical error in monitor_files: {e}")


def monitor_ssh_attempts():
    """
    Monitors SSH login attempts by tailing the host's auth log.
    """
    try:
        logging.info("Monitoring SSH login attempts.")
        ssh_log_path = "/host_var_log/auth.log"  # Adjust this path if necessary

        if not os.path.exists(ssh_log_path):
            logging.error(f"SSH log file does not exist: {ssh_log_path}")
            return

        failed_attempts = {}
        MAX_ATTEMPTS = 5  # Threshold for brute-force detection

        # Ensure 'tail' is available
        if not shutil.which("tail"):
            logging.error(
                "'tail' command not found. Install 'coreutils' package in the Dockerfile."
            )
            return

        with Popen(
            ["tail", "-F", ssh_log_path],
            stdout=PIPE,
            stderr=PIPE,
            universal_newlines=True,
        ) as p:
            for line in p.stdout:
                try:
                    line = line.strip()
                    if not line:
                        continue

                    # Failed SSH login attempt
                    if "Failed password for" in line:
                        alert_message = f"Failed SSH login attempt detected: {line}"
                        logging.warning(alert_message)

                        # Brute-force detection
                        match = re.search(
                            r"Failed password for .* from ([\d\.]+) port", line
                        )
                        if match:
                            ip_address = match.group(1)
                            failed_attempts[ip_address] = (
                                failed_attempts.get(ip_address, 0) + 1
                            )
                            if failed_attempts[ip_address] >= MAX_ATTEMPTS:
                                alert_message = f"Possible brute-force attack detected from {ip_address}"
                                logging.warning(alert_message)
                                # Reset counter or take action
                                failed_attempts[ip_address] = 0

                    # Successful SSH login
                    elif "Accepted password for" in line:
                        alert_message = f"Successful SSH login detected: {line}"
                        logging.info(alert_message)
                except Exception as e:
                    logging.error(f"Error processing SSH log line: {e}")
    except Exception as e:
        logging.error(f"Critical error in monitor_ssh_attempts: {e}")


def monitor_container_escape_attempts():
    """
    Monitors for potential container escape attempts.
    """
    try:
        logging.info("Monitoring for container escape attempts.")

        # Paths that should not be accessible from within the container
        sensitive_host_paths = ["/host_root", "/proc/host"]

        while True:
            try:
                for path in sensitive_host_paths:
                    if os.path.exists(path):
                        alert_message = f"Potential container escape attempt detected: Access to {path}"
                        logging.warning(alert_message)
                time.sleep(5)
            except Exception as e:
                logging.error(f"Error in container escape monitoring loop: {e}")
                time.sleep(5)
    except Exception as e:
        logging.error(f"Critical error in monitor_container_escape_attempts: {e}")


def main():
    try:
        logging.info("IDS initialized.")
        threads = []
        process_thread = threading.Thread(target=monitor_processes)
        threads.append(process_thread)
        file_thread = threading.Thread(
            target=monitor_files, args=(["/etc", "/var", "/home", "/tmp"],)
        )
        threads.append(file_thread)
        ssh_thread = threading.Thread(target=monitor_ssh_attempts)
        threads.append(ssh_thread)
        process_creation_thread = threading.Thread(target=monitor_process_creations)
        threads.append(process_creation_thread)
        escape_thread = threading.Thread(target=monitor_container_escape_attempts)
        threads.append(escape_thread)

        for thread in threads:
            thread.daemon = True
            thread.start()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("IDS shutting down.")
    except Exception as e:
        logging.error(f"Critical error in main: {e}")


if __name__ == "__main__":
    main()
