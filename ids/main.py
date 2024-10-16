import logging
import sys
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import re
import shutil
import os
from subprocess import Popen, PIPE

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,  # Set to DEBUG for more detailed logs
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,  # Log to stdout
)


def monitor_processes():
    try:
        logging.info("Process monitoring started.")
        SENSITIVE_BINARIES = [
            "/usr/bin/python3",
            "/bin/bash",
            "/bin/sh",
            "/bin/sleep",
        ]

        WHITELISTED_PROCESSES = [
            "supervisord",
            "python",
            "python3",
            "tail",
            "sh",
            "sshd",
            "ids.py",
            "bash",
        ]

        CRITICAL_READ_PATHS = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
            "/proc/1/ns/net",
            "/proc/1/cmdline",
        ]

        # Normalize critical paths to their real paths
        CRITICAL_READ_PATHS_REALPATH = [
            os.path.realpath(p) for p in CRITICAL_READ_PATHS
        ]

        while True:
            try:
                for proc in psutil.process_iter(
                    ["pid", "name", "username", "exe", "cmdline", "uids", "status"]
                ):
                    process_name = proc.info.get("name", "").lower()
                    process_info = (
                        f"Process: {process_name} (PID: {proc.info['pid']}, "
                        f"User: {proc.info.get('username')}, "
                        f"CMD: {' '.join(proc.info.get('cmdline') or [])})"
                    )

                    # Detect container escape attempts via nsenter or accessing /proc/1/ns/.
                    if "nsenter" in process_name or "/proc/1/ns/" in " ".join(
                        proc.info.get("cmdline", [])
                    ):
                        logging.warning(
                            f"Potential container escape detected: {process_info}"
                        )

                    # Detect processes running as root that are not whitelisted
                    if (
                        proc.info.get("username") == "root"
                        and proc.info["pid"] != 1
                        and process_name
                        not in [p.lower() for p in WHITELISTED_PROCESSES]
                    ):
                        alert_message = (
                            f"Suspicious root process detected: {process_info}"
                        )
                        logging.warning(alert_message)

                    # Detect execution of sensitive binaries
                    exe = proc.info.get("exe") or ""
                    exe_realpath = os.path.realpath(exe)
                    if exe_realpath in SENSITIVE_BINARIES:
                        alert_message = (
                            f"Sensitive binary execution detected: {process_info}"
                        )
                        logging.warning(alert_message)

                    # Detect privilege escalation
                    uids = proc.info.get("uids")
                    if uids and uids.real != uids.effective:
                        alert_message = f"Privilege escalation detected: {process_info}"
                        logging.warning(alert_message)

                    # Monitor for processes attempting to access critical files
                    cmdline = proc.info.get("cmdline", [])
                    for arg in cmdline:
                        # Resolve the real path of the argument
                        arg_realpath = os.path.realpath(arg)
                        if arg_realpath in CRITICAL_READ_PATHS_REALPATH:
                            alert_message = f"Process attempting to access critical file: {process_info}"
                            logging.warning(alert_message)
                            break  # No need to check other args if one is critical

                    # Check open files of the process
                    try:
                        open_files = proc.open_files()
                        for f in open_files:
                            file_path = os.path.realpath(f.path)
                            if file_path in CRITICAL_READ_PATHS_REALPATH:
                                alert_message = (
                                    f"Process has critical file open: {process_info}"
                                )
                                logging.warning(alert_message)
                                break  # No need to check other files
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Process terminated or access denied to its file descriptors
                        continue

                time.sleep(1)
            except Exception as e:
                logging.error(f"Error in process monitoring loop: {e}")
                time.sleep(1)
    except Exception as e:
        logging.error(f"Critical error in monitor_processes: {e}")


def monitor_process_creations():
    """
    Monitors for new process creations.
    Logs details of new processes, excluding the IDS script itself.
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
    Logs creation, modification, deletion, and movement of critical files.
    """

    def __init__(self):
        super().__init__()
        self.excluded_dirs = ["/host_var_log", "/var/log/ids_app"]
        self.critical_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
            "/etc/passwd_test.txt",
            "/tmp",
        ]
        self.normalized_critical_paths = [
            os.path.realpath(path) for path in self.critical_paths
        ]
        self.normalized_excluded_dirs = [
            os.path.realpath(path) for path in self.excluded_dirs
        ]

    def on_any_event(self, event):
        try:
            event_src_path = os.path.realpath(event.src_path)

            # Check if the event is in an excluded directory
            if any(
                event_src_path.startswith(excluded_dir)
                for excluded_dir in self.normalized_excluded_dirs
            ):
                # Lower log level for excluded paths to DEBUG to avoid spam
                logging.debug(f"Ignoring event on excluded path: {event_src_path}")
                return

            if not event.is_directory:
                # Check if the event is happening in a critical path
                if any(
                    event_src_path.startswith(path)
                    for path in self.normalized_critical_paths
                ):
                    if event.event_type in ("modified", "deleted", "created", "moved"):
                        alert_message = (
                            f"Critical file {event.event_type}: {event_src_path}"
                        )
                        logging.warning(alert_message)
                else:
                    logging.info(
                        f"Non-critical event: {event.event_type} on {event_src_path}"
                    )
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
                observer.schedule(
                    event_handler, path=path, recursive=True
                )  # Set recursive to True
                logging.info(f"Monitoring path: {path}")
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
    Monitors SSH login attempts by tailing external log files.
    Logs failed and successful login attempts, and detects possible brute-force attacks.
    """
    try:
        logging.info("Monitoring SSH login attempts.")
        ssh_log_paths = [
            "/host_var_log/auth.log",
            "/host_var_log/syslog",
        ]  # External logs

        for ssh_log_path in ssh_log_paths:
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

        # Start tailing each log file in separate threads
        for ssh_log_path in ssh_log_paths:
            thread = threading.Thread(
                target=tail_log_file,
                args=(ssh_log_path, failed_attempts, MAX_ATTEMPTS),
            )
            thread.daemon = True
            thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except Exception as e:
        logging.error(f"Critical error in monitor_ssh_attempts: {e}")


def tail_log_file(ssh_log_path, failed_attempts, MAX_ATTEMPTS):
    """
    Tails a single log file and processes SSH login attempts.
    """
    try:
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
        logging.error(f"Critical error in tail_log_file ({ssh_log_path}): {e}")


def main():
    try:
        logging.info("IDS initialized.")
        threads = []

        # Start process monitoring thread
        process_thread = threading.Thread(target=monitor_processes)
        threads.append(process_thread)

        # Start file monitoring thread
        file_thread = threading.Thread(
            target=monitor_files, args=(["/etc", "/var", "/home", "/tmp"],)
        )
        threads.append(file_thread)

        # Start SSH attempts monitoring thread
        ssh_thread = threading.Thread(target=monitor_ssh_attempts)
        threads.append(ssh_thread)

        # Start process creation monitoring thread
        process_creation_thread = threading.Thread(target=monitor_process_creations)
        threads.append(process_creation_thread)

        # Start all threads
        for thread in threads:
            thread.daemon = True
            thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("IDS shutting down.")
    except Exception as e:
        logging.error(f"Critical error in main: {e}")


if __name__ == "__main__":
    main()
