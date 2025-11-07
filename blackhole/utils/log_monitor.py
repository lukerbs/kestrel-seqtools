"""
AnyDesk Log Monitor - Watches log files for connection events
Uses watchdog library for efficient file monitoring
"""

import os
import re
import threading
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class LogFileHandler(FileSystemEventHandler):
    """
    Handles file modification events for AnyDesk log files.
    Implements tailing logic to only read new content.
    """

    def __init__(self, callback, log_func=None):
        """
        Initialize the log file handler.

        Args:
            callback: Function to call with parsed events
            log_func: Optional logging function
        """
        super().__init__()
        self._callback = callback
        self._log = log_func if log_func else lambda msg: None
        self._file_positions = {}  # Track last read position for each file
        self._lock = threading.Lock()

        # Regex patterns for parsing
        self._incoming_pattern = re.compile(
            r"Incoming\s+(\d{4}-\d{2}-\d{2}),\s+(\d{2}:\d{2})\s+\w+\s+(\d{9,10})\s+\d{9,10}"
        )
        self._ip_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+).*Logged in from\s+([\d.]+):\d+")
        self._outgoing_rejected_pattern = re.compile(
            r"Outgoing\s+(\d{4}-\d{2}-\d{2}),\s+(\d{2}:\d{2})\s+REJECTED\s+(\d{9,10})\s+\d{9,10}"
        )
        self._outgoing_accepted_pattern = re.compile(
            r"Outgoing\s+(\d{4}-\d{2}-\d{2}),\s+(\d{2}:\d{2})\s+User\s+(\d{9,10})\s+\d{9,10}"
        )

    def on_modified(self, event):
        """Called when a file is modified"""
        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        # Only process AnyDesk log files
        if filename == "connection_trace.txt":
            self._process_connection_trace(event.src_path)
        elif filename == "ad_svc.trace" or filename == "ad.trace":
            self._process_ad_trace(event.src_path)

    def _process_connection_trace(self, filepath):
        """
        Process connection_trace.txt for incoming/outgoing connection events.
        """
        try:
            with self._lock:
                # Get last read position
                last_pos = self._file_positions.get(filepath, 0)

                # Read new content
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    # Check if file was rotated (size decreased)
                    f.seek(0, os.SEEK_END)
                    file_size = f.tell()

                    if file_size < last_pos:
                        # File was rotated, start from beginning
                        self._log(f"[LOG_MONITOR] Detected log rotation: {filepath}")
                        last_pos = 0

                    # Seek to last position and read new lines
                    f.seek(last_pos)
                    new_lines = f.readlines()

                    # Update position
                    self._file_positions[filepath] = f.tell()

                # Parse new lines
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Check for incoming connection
                    match = self._incoming_pattern.search(line)
                    if match:
                        date_str, time_str, anydesk_id = match.groups()
                        timestamp = f"{date_str} {time_str}:00"  # Add seconds
                        self._callback(
                            "incoming_id", {"anydesk_id": anydesk_id, "timestamp": timestamp, "raw_line": line}
                        )
                        continue

                    # Check for outgoing rejection
                    match = self._outgoing_rejected_pattern.search(line)
                    if match:
                        date_str, time_str, anydesk_id = match.groups()
                        timestamp = f"{date_str} {time_str}:00"
                        self._callback(
                            "outgoing_rejected", {"anydesk_id": anydesk_id, "timestamp": timestamp, "raw_line": line}
                        )
                        continue

                    # Check for outgoing accepted (successful connection)
                    match = self._outgoing_accepted_pattern.search(line)
                    if match:
                        date_str, time_str, anydesk_id = match.groups()
                        timestamp = f"{date_str} {time_str}:00"
                        self._callback(
                            "outgoing_accepted", {"anydesk_id": anydesk_id, "timestamp": timestamp, "raw_line": line}
                        )
                        continue

        except Exception as e:
            self._log(f"[LOG_MONITOR] Error processing connection_trace.txt: {e}")

    def _process_ad_trace(self, filepath):
        """
        Process ad_svc.trace (or ad.trace) for IP addresses.
        """
        try:
            with self._lock:
                # Get last read position
                last_pos = self._file_positions.get(filepath, 0)

                # Read new content
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    # Check if file was rotated
                    f.seek(0, os.SEEK_END)
                    file_size = f.tell()

                    if file_size < last_pos:
                        self._log(f"[LOG_MONITOR] Detected log rotation: {filepath}")
                        last_pos = 0

                    # Seek to last position and read new lines
                    f.seek(last_pos)
                    new_lines = f.readlines()

                    # Update position
                    self._file_positions[filepath] = f.tell()

                # Parse new lines
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Check for "Logged in from" (incoming connection IP)
                    match = self._ip_pattern.search(line)
                    if match:
                        timestamp_str, ip_address = match.groups()
                        # Convert timestamp to match connection_trace format (minute precision)
                        # "2025-11-06 13:36:43.933" -> "2025-11-06 13:36:00"
                        dt = datetime.strptime(timestamp_str.split(".")[0], "%Y-%m-%d %H:%M:%S")
                        timestamp = dt.strftime("%Y-%m-%d %H:%M:00")

                        self._callback(
                            "incoming_ip", {"ip_address": ip_address, "timestamp": timestamp, "raw_line": line}
                        )

        except Exception as e:
            self._log(f"[LOG_MONITOR] Error processing ad_svc.trace: {e}")


class LogMonitor:
    """
    Monitors AnyDesk log directories for connection events.
    Uses watchdog to efficiently watch multiple directories.
    """

    def __init__(self, callback, log_func=None):
        """
        Initialize the log monitor.

        Args:
            callback: Function to call with parsed events
            log_func: Optional logging function
        """
        self._callback = callback
        self._log = log_func if log_func else lambda msg: None
        self._observer = Observer()
        self._handler = LogFileHandler(callback, log_func)
        self._running = False

        # Determine log directories to monitor
        self._log_dirs = self._get_log_directories()

    def _get_log_directories(self):
        """
        Get list of AnyDesk log directories that exist on the system.
        """
        dirs = []

        # Installed version (requires admin)
        installed_path = r"C:\ProgramData\AnyDesk"
        if os.path.exists(installed_path):
            dirs.append(installed_path)

        # Portable version (user profile)
        appdata = os.getenv("APPDATA", "")
        if appdata:
            portable_path = os.path.join(appdata, "AnyDesk")
            if os.path.exists(portable_path):
                dirs.append(portable_path)

        return dirs

    def start(self):
        """Start monitoring log directories"""
        if self._running:
            self._log("[LOG_MONITOR] Already running")
            return

        if not self._log_dirs:
            self._log("[LOG_MONITOR] No AnyDesk log directories found")
            return

        self._log("[LOG_MONITOR] Starting log monitoring...")
        for log_dir in self._log_dirs:
            self._log(f"[LOG_MONITOR] Watching: {log_dir}")
            self._observer.schedule(self._handler, log_dir, recursive=False)

        self._observer.start()
        self._running = True
        self._log("[LOG_MONITOR] Log monitoring active")

    def stop(self):
        """Stop monitoring"""
        if not self._running:
            return

        self._log("[LOG_MONITOR] Stopping log monitoring...")
        self._observer.stop()
        self._observer.join(timeout=5)
        self._running = False
        self._log("[LOG_MONITOR] Log monitoring stopped")

    def is_running(self):
        """Check if monitor is running"""
        return self._running
