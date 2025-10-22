"""
Process Monitor - Detects and tracks target remote desktop processes
"""

import psutil
import time
import threading

from .config import TARGET_PROCESSES, PROCESS_SCAN_INTERVAL


class ProcessMonitor:
    """
    Monitors for remote desktop processes and notifies via callback.
    Runs in a background thread and polls the process list periodically.
    """

    def __init__(self, log_func=None, callback=None):
        """
        Initialize the process monitor.

        Args:
            log_func: Optional logging function
            callback: Function called when process found/lost.
                     Signature: callback(event_type, pid, process_name)
                     event_type is 'found' or 'lost'
        """
        self._log = log_func if log_func else lambda msg: None
        self._callback = callback
        self._tracked_pids = {}  # {pid: process_name}
        self._running = False
        self._thread = None

    def start(self):
        """Start monitoring for target processes"""
        if self._running:
            self._log("[MONITOR] Already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ProcessMonitor")
        self._thread.start()
        self._log("[MONITOR] Process monitoring started")
        self._log(f"[MONITOR] Scanning for: {', '.join(TARGET_PROCESSES)}")

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

                # Scan for target processes
                for proc in psutil.process_iter(["pid", "name"]):
                    try:
                        name = proc.info["name"]
                        if name in TARGET_PROCESSES:
                            pid = proc.info["pid"]
                            current_pids[pid] = name

                            # New process found
                            if pid not in self._tracked_pids:
                                self._log(f"[MONITOR] Detected: {name} (PID: {pid})")
                                if self._callback:
                                    try:
                                        self._callback("found", pid, name)
                                    except Exception as e:
                                        self._log(f"[MONITOR] Callback error: {e}")

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        # Process disappeared or we don't have access
                        pass

                # Check for processes that disappeared
                for pid, name in list(self._tracked_pids.items()):
                    if pid not in current_pids:
                        self._log(f"[MONITOR] Lost: {name} (PID: {pid})")
                        if self._callback:
                            try:
                                self._callback("lost", pid, name)
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
