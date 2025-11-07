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
        self._file_positions = {}  # bytes offset per file
        self._file_remainders = {}  # str tail per file (for partial lines)
        self._file_stats = {}  # (size, mtime) for debounce
        self._lock = threading.Lock()

        # Regex patterns for parsing
        # Single unified pattern for connection_trace.txt (handles Incoming/Outgoing + User/REJECTED)
        self._connection_pattern = re.compile(
            r"^(?P<direction>\w+)\s+(?P<date>\d{4}-\d{2}-\d{2}),\s*(?P<time>\d{2}:\d{2})\s+"
            r"(?P<status>\w+)\s+(?P<id1>\d+)\s+(?P<id2>\d+)$"
        )
        # Pattern for IP addresses in ad_svc.trace / ad.trace (IPv4/IPv6, case-insensitive)
        self._ip_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
            r".*?\blogged in from\b\s+([0-9a-fA-F:.\[\]]+)(?::\d+)?",
            re.I,
        )

    def on_modified(self, event):
        """Called when a file is modified"""
        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        # Debug logging
        self._log(f"[LOG_MONITOR] File modified: {filename}")

        # Only process AnyDesk log files
        if filename == "connection_trace.txt":
            self._log(f"[LOG_MONITOR] Processing connection_trace.txt modification...")
            self._process_connection_trace(event.src_path)
        elif filename == "ad_svc.trace" or filename == "ad.trace":
            self._log(f"[LOG_MONITOR] Processing {filename} modification...")
            self._process_ad_trace(event.src_path)

    def _decode(self, b: bytes) -> str:
        """
        Decode bytes with automatic encoding detection.
        Handles UTF-16 LE/BE, UTF-8 with BOM, and heuristic fallback.
        """
        if b.startswith(b"\xff\xfe") or b.startswith(b"\xfe\xff"):
            return b.decode("utf-16", errors="replace")
        if b.startswith(b"\xef\xbb\xbf"):
            return b.decode("utf-8-sig", errors="replace")
        # Heuristic: lots of NULs -> UTF-16LE
        if b[:200].count(b"\x00") > 10:
            return b.decode("utf-16-le", errors="replace")
        return b.decode("utf-8", errors="replace")

    def _read_new_bytes(self, filepath):
        """
        Read new bytes from file with debouncing and rotation detection.
        Returns empty bytes if no changes detected (debounce).
        """
        # Debounce duplicate on_modified events
        try:
            st = os.stat(filepath)
        except FileNotFoundError:
            return b""

        sig = (st.st_size, int(st.st_mtime))
        if self._file_stats.get(filepath) == sig:
            return b""  # No actual changes
        self._file_stats[filepath] = sig

        last_pos = self._file_positions.get(filepath, 0)
        with open(filepath, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size < last_pos:
                # Rotation/truncate detected
                self._log(f"[LOG_MONITOR] Rotation/truncate detected: {filepath}")
                last_pos = 0
                # Clear remainder for this file
                self._file_remainders.pop(filepath, None)
            f.seek(last_pos)
            new = f.read()
            self._file_positions[filepath] = f.tell()
        return new

    def _iter_new_lines(self, filepath, is_connection: bool):
        """
        Iterate new lines from file with remainder handling for partial lines.

        Args:
            filepath: Path to file
            is_connection: If True, normalize whitespace (for connection_trace.txt)

        Returns:
            List of complete lines
        """
        new_bytes = self._read_new_bytes(filepath)
        if not new_bytes:
            return []

        text = self._decode(new_bytes)

        # Remainder handling for partial lines
        buf = self._file_remainders.get(filepath, "")
        buf += text
        lines = buf.splitlines(keepends=False)

        # If file does not end with newline, last item may be partial
        if buf and not buf.endswith(("\n", "\r")):
            self._file_remainders[filepath] = lines.pop() if lines else buf
        else:
            self._file_remainders[filepath] = ""

        # Normalize whitespace for connection_trace only
        if is_connection:
            lines = [" ".join(l.strip().split()) for l in lines if l.strip()]
        else:
            lines = [l.strip() for l in lines if l.strip()]
        return lines

    def _process_connection_trace(self, filepath):
        """
        Process connection_trace.txt for incoming/outgoing connection events.
        Uses robust remainder handling and encoding detection.
        """
        try:
            with self._lock:
                lines = self._iter_new_lines(filepath, is_connection=True)

            self._log(f"[LOG_MONITOR] Read {len(lines)} new lines from connection_trace.txt")
            for line in lines:
                self._log(f"[LOG_MONITOR] Parsing line: {line}")

                m = self._connection_pattern.match(line)
                if not m:
                    self._log(f"[LOG_MONITOR] No pattern matched for line: {line}")
                    continue

                g = m.groupdict()
                direction, status = g["direction"], g["status"]
                anydesk_id = g["id1"]
                timestamp = f"{g['date']} {g['time']}:00"  # Synthesized seconds (documented)

                self._log(f"[LOG_MONITOR] MATCHED: {direction} {status} ID={anydesk_id} at {timestamp}")

                payload = {"anydesk_id": anydesk_id, "timestamp": timestamp, "raw_line": line}

                # Wrap callback to prevent one failure from aborting batch
                try:
                    if direction == "Incoming" and status == "User":
                        self._callback("incoming_id", payload)
                    elif direction == "Incoming" and status == "REJECTED":
                        self._log(f"[LOG_MONITOR] Incoming connection rejected from {anydesk_id}")
                    elif direction == "Outgoing" and status == "REJECTED":
                        self._callback("outgoing_rejected", payload)
                    elif direction == "Outgoing" and status == "User":
                        self._callback("outgoing_accepted", payload)
                except Exception as cb_err:
                    self._log(f"[LOG_MONITOR] Callback error: {cb_err}")

        except Exception as e:
            self._log(f"[LOG_MONITOR] Error processing connection_trace.txt: {e}")

    def _process_ad_trace(self, filepath):
        """
        Process ad_svc.trace (or ad.trace) for IP addresses.
        Uses robust remainder handling and encoding detection.
        """
        try:
            with self._lock:
                lines = self._iter_new_lines(filepath, is_connection=False)

            self._log(f"[LOG_MONITOR] Read {len(lines)} new lines from {os.path.basename(filepath)}")
            for line in lines:
                m = self._ip_pattern.search(line)
                if not m:
                    continue

                ts_raw, ip = m.groups()
                # Normalize time to minute precision
                try:
                    ts = ts_raw.split(".")[0]  # Remove milliseconds
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:00")
                except ValueError:
                    timestamp = ts_raw  # Fallback: keep raw timestamp

                self._log(f"[LOG_MONITOR] MATCHED incoming_ip: {ip} at {timestamp}")

                # Wrap callback to prevent one failure from aborting batch
                try:
                    self._callback("incoming_ip", {"ip_address": ip, "timestamp": timestamp, "raw_line": line})
                except Exception as cb_err:
                    self._log(f"[LOG_MONITOR] Callback error: {cb_err}")

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

    def _initialize_file_positions(self):
        """
        Initialize file positions and process existing log content on startup.
        This helps catch connections that happened just before startup.
        """
        self._log("[LOG_MONITOR] Initializing file positions...")

        # Clear remainder state on initialization
        self._handler._file_remainders.clear()

        for log_dir in self._log_dirs:
            # Check for connection_trace.txt
            connection_trace = os.path.join(log_dir, "connection_trace.txt")
            if os.path.exists(connection_trace):
                self._log(f"[LOG_MONITOR] Found connection_trace.txt in {log_dir}")
                # Force process the entire file once on startup
                self._handler._process_connection_trace(connection_trace)

            # Check for ad_svc.trace
            ad_svc_trace = os.path.join(log_dir, "ad_svc.trace")
            if os.path.exists(ad_svc_trace):
                self._log(f"[LOG_MONITOR] Found ad_svc.trace in {log_dir}")
                # Set position to end of file (we don't want to process all historical IPs)
                try:
                    with open(ad_svc_trace, "rb") as f:
                        f.seek(0, os.SEEK_END)
                        self._handler._file_positions[ad_svc_trace] = f.tell()
                        self._log(f"[LOG_MONITOR] Set ad_svc.trace position to end ({f.tell()} bytes)")
                    # Clear remainder for this file
                    self._handler._file_remainders.pop(ad_svc_trace, None)
                except Exception as e:
                    self._log(f"[LOG_MONITOR] Error initializing ad_svc.trace: {e}")

            # Check for ad.trace (portable version)
            ad_trace = os.path.join(log_dir, "ad.trace")
            if os.path.exists(ad_trace):
                self._log(f"[LOG_MONITOR] Found ad.trace in {log_dir}")
                try:
                    with open(ad_trace, "rb") as f:
                        f.seek(0, os.SEEK_END)
                        self._handler._file_positions[ad_trace] = f.tell()
                        self._log(f"[LOG_MONITOR] Set ad.trace position to end ({f.tell()} bytes)")
                    # Clear remainder for this file
                    self._handler._file_remainders.pop(ad_trace, None)
                except Exception as e:
                    self._log(f"[LOG_MONITOR] Error initializing ad.trace: {e}")

        self._log("[LOG_MONITOR] File position initialization complete")

    def start(self):
        """Start monitoring log directories"""
        if self._running:
            self._log("[LOG_MONITOR] Already running")
            return

        if not self._log_dirs:
            self._log("[LOG_MONITOR] No AnyDesk log directories found")
            return

        self._log("[LOG_MONITOR] Starting log monitoring...")

        # Initialize file positions by reading existing content
        self._initialize_file_positions()

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
