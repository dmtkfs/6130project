import logging
import sys
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import re
import os
from subprocess import call
from collections import defaultdict
import signal  # Added import signal

# Configure logging
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/var/log/ids_app/ids.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# Global Variables (load from environment)
BLACKLIST_FILE = os.getenv("BLACKLIST_FILE", "/var/log/ids_app/blacklist.txt")
FAILED_ATTEMPTS_THRESHOLD = int(os.getenv("FAILED_ATTEMPTS_THRESHOLD", "3"))
SSH_LOG_PATH = LOG_FILE_PATH  # SSH logs are in the same file
SSHD_CONFIG_PATH = os.getenv("SSHD_CONFIG_PATH", "/etc/ssh/sshd_config")


def monitor_processes():
    try:
        logging.info("Process monitoring started.")
        SENSITIVE_BINARIES = [
            "/usr/bin/python3.12",
            "/bin/bash",
            "/bin/sh",
            "/bin/ash",
            "/bin/zsh",
            "/bin/busybox",
            "/bin/sleep",
        ]

        WHITELISTED_PROCESSES = [
            "supervisord",
            "supervisorctl",
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

                        # Additional check for python3 commands
                        if (
                            exe_realpath == "/usr/bin/python3"
                            and len(proc.info.get("cmdline", [])) > 1
                        ):
                            command_args = " ".join(proc.info.get("cmdline")[1:])
                            if re.search(r"-c\s+'.+'", command_args) or re.search(
                                r"--some-malicious-flag", command_args
                            ):
                                logging.warning(
                                    f"Malicious python3 command detected: {process_info}"
                                )

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
    SENSITIVE_BINARIES = [
        "/usr/bin/python3.12",
        "/bin/bash",
        "/bin/sh",
        "/bin/ash",
        "/bin/zsh",
        "/bin/busybox",
        "/bin/sleep",
    ]

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

                            # Additional check for sensitive binaries
                            exe_realpath = os.path.realpath(proc.exe())
                            if exe_realpath in SENSITIVE_BINARIES:
                                alert_message = f"Sensitive binary execution detected via process creation: {process_info}"
                                logging.warning(alert_message)

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
        self.excluded_dirs = ["/var/log/ids_app"]
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
    Monitors SSH login attempts by reading from the shared log file.
    Logs failed and successful login attempts, detects possible brute-force attacks,
    and implements IP jail functionality.
    """
    try:
        logging.info("Monitoring SSH login attempts.")

        # Ensure the blacklist file exists
        if not os.path.exists(BLACKLIST_FILE):
            open(BLACKLIST_FILE, "w").close()

        failed_attempts = defaultdict(int)

        # Regular expressions to match SSH log entries
        failed_login_pattern = re.compile(
            r"Failed password for (?:invalid user )?(.*) from (\d+\.\d+\.\d+\.\d+) port \d+"
        )
        invalid_user_pattern = re.compile(
            r"Invalid user (.*) from (\d+\.\d+\.\d+\.\d+) port \d+"
        )
        accepted_login_pattern = re.compile(
            r"Accepted password for (.*) from (\d+\.\d+\.\d+\.\d+) port \d+"
        )

        # Open the shared log file
        with open(SSH_LOG_PATH, "r") as log_file:
            # Seek to the end of the file
            log_file.seek(0, os.SEEK_END)
            while True:
                line = log_file.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                # Load existing blacklisted IPs
                blacklisted_ips = load_blacklisted_ips()

                # Process the log line
                ip_address = None
                if "Failed password" in line:
                    match = failed_login_pattern.search(line)
                    if match:
                        user = match.group(1)
                        ip_address = match.group(2)
                        failed_attempts[ip_address] += 1
                        logging.info(
                            f"Failed login attempt for user '{user}' from {ip_address}. Count: {failed_attempts[ip_address]}"
                        )

                elif "Invalid user" in line:
                    match = invalid_user_pattern.search(line)
                    if match:
                        user = match.group(1)
                        ip_address = match.group(2)
                        failed_attempts[ip_address] += 1
                        logging.info(
                            f"Invalid user '{user}' login attempt from {ip_address}. Count: {failed_attempts[ip_address]}"
                        )

                elif "Accepted password" in line:
                    match = accepted_login_pattern.search(line)
                    if match:
                        user = match.group(1)
                        ip_address = match.group(2)
                        # Reset failed attempts on successful login
                        if ip_address in failed_attempts:
                            del failed_attempts[ip_address]
                        logging.info(
                            f"Successful login for user '{user}' from {ip_address}"
                        )
                        continue  # Successful login, no action needed

                # Check if IP should be blacklisted
                if ip_address and should_blacklist_ip(
                    ip_address, failed_attempts, blacklisted_ips
                ):
                    blacklist_ip(ip_address, blacklisted_ips)
                    update_sshd_config(blacklisted_ips)
                    reload_ssh_service()
                else:
                    # Update sshd_config if blacklisted_ips has changed
                    previous_blacklisted_ips = getattr(
                        monitor_ssh_attempts, "previous_blacklisted_ips", set()
                    )
                    if blacklisted_ips != previous_blacklisted_ips:
                        update_sshd_config(blacklisted_ips)
                        reload_ssh_service()
                        monitor_ssh_attempts.previous_blacklisted_ips = blacklisted_ips

    except Exception as e:
        logging.error(f"Critical error in monitor_ssh_attempts: {e}")


def load_blacklisted_ips():
    """Load blacklisted IPs from the blacklist file."""
    if not os.path.exists(BLACKLIST_FILE):
        open(BLACKLIST_FILE, "w").close()
    with open(BLACKLIST_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())


def should_blacklist_ip(ip_address, failed_attempts, blacklisted_ips):
    """Determine if an IP should be blacklisted."""
    if ip_address in blacklisted_ips:
        return False  # Already blacklisted
    if failed_attempts[ip_address] >= FAILED_ATTEMPTS_THRESHOLD:
        return True
    return False


def blacklist_ip(ip_address, blacklisted_ips):
    """Add an IP to the blacklist file."""
    blacklisted_ips.add(ip_address)
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip_address + "\n")
    logging.warning(f"IP {ip_address} has been blacklisted.")


def update_sshd_config(blacklisted_ips):
    """Update sshd_config with blacklisted IPs."""
    try:
        with open(SSHD_CONFIG_PATH, "r") as f:
            config_lines = f.readlines()

        # Remove existing Match Address blocks
        new_config_lines = []
        skip = False
        for line in config_lines:
            if line.strip().startswith("Match Address"):
                skip = True
                continue
            if skip and line.startswith("    DenyUsers *"):
                continue
            if skip and not line.startswith(" "):
                skip = False
            if not skip:
                new_config_lines.append(line)

        # Add new Match Address blocks
        for ip in blacklisted_ips:
            new_config_lines.append(f"\nMatch Address {ip}\n")
            new_config_lines.append("    DenyUsers *\n")

        # Write back the updated config
        with open(SSHD_CONFIG_PATH, "w") as f:
            f.writelines(new_config_lines)

        logging.info("sshd_config has been updated with blacklisted IPs.")

    except Exception as e:
        logging.error(f"Failed to update sshd_config: {e}")


def reload_ssh_service():
    """Reload the SSH service to apply configuration changes."""
    try:
        sshd_pid_file = "/var/run/sshd.pid"
        if os.path.exists(sshd_pid_file):
            with open(sshd_pid_file, "r") as f:
                sshd_pid = int(f.read().strip())
            os.kill(sshd_pid, signal.SIGHUP)
            logging.info("SSH service reloaded successfully.")
        else:
            logging.error("sshd PID file not found.")
    except Exception as e:
        logging.error(f"Error reloading SSH service: {e}")


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
