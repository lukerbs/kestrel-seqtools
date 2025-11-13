"""
Process Monitor - Detects and tracks target remote desktop processes
"""

import psutil
import time
import threading

from ..config import PROCESS_SCAN_INTERVAL


class ProcessMonitor:
    """
    Monitors ALL processes and notifies via callback when they start/stop.
    Runs in a background thread and polls the process list periodically.
    Whitelist/blacklist filtering is handled by the caller.
    """

    def __init__(self, log_func=None, callback=None):
        """
        Initialize the process monitor.

        Args:
            log_func: Optional logging function
            callback: Function called when process found/lost.
                     Signature: callback(event_type, pid, process_name, exe_path, cmdline)
                     event_type is 'found' or 'lost'
        """
        self._log = log_func if log_func else lambda msg: None
        self._callback = callback
        self._tracked_pids = {}  # {pid: (process_name, exe_path, cmdline)}
        self._running = False
        self._thread = None

    def start(self):
        """Start monitoring for all processes"""
        if self._running:
            self._log("[MONITOR] Already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ProcessMonitor")
        self._thread.start()
        self._log("[MONITOR] Process monitoring started")
        self._log("[MONITOR] Monitoring ALL processes (whitelist/blacklist managed by service)")

    def stop(self):
        """Stop monitoring"""
        if not self._running:
            return

        self._log("[MONITOR] Stopping process monitoring...")
        self._running = False

        if self._thread:
            self._thread.join(timeout=5)

        self._log("[MONITOR] Process monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop - runs in background thread"""
        while self._running:
            try:
                current_pids = {}

                # Scan ALL processes (request 'exe' and 'cmdline' attributes)
                for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                    try:
                        name = proc.info["name"]
                        pid = proc.info["pid"]
                        exe_path = proc.info.get("exe")  # Get exe path
                        cmdline = proc.info.get("cmdline", [])  # Get command line

                        # Skip processes without exe path (kernel processes)
                        if not exe_path:
                            continue

                        current_pids[pid] = (name, exe_path, cmdline)  # Store all

                        # New process found
                        if pid not in self._tracked_pids:
                            if self._callback:
                                try:
                                    # Pass exe_path and cmdline
                                    self._callback("found", pid, name, exe_path, cmdline)
                                except Exception as e:
                                    self._log(f"[MONITOR] Callback error: {e}")

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        # Process disappeared or we don't have access
                        pass

                # Check for processes that disappeared
                for pid, (name, exe_path, cmdline) in list(self._tracked_pids.items()):
                    if pid not in current_pids:
                        self._log(f"[MONITOR] Lost: {name} (PID: {pid})")
                        if self._callback:
                            try:
                                # Pass None for exe_path and cmdline on 'lost'
                                self._callback("lost", pid, name, None, None)
                            except Exception as e:
                                self._log(f"[MONITOR] Callback error: {e}")

                # Update tracked processes
                self._tracked_pids = current_pids

            except Exception as e:
                self._log(f"[MONITOR] Error in monitoring loop: {e}")

            # Sleep before next scan
            time.sleep(PROCESS_SCAN_INTERVAL)

    def get_tracked_processes(self):
        """
        Get currently tracked processes.

        Returns:
            dict: {pid: process_name}
        """
        return self._tracked_pids.copy()

    def is_running(self):
        """Check if monitor is running"""
        return self._running
