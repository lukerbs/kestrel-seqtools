"""
Connection Correlator - Matches split metadata from AnyDesk log files
Correlates AnyDesk IDs with IP addresses using time-based matching
"""

import threading
import time
from datetime import datetime, timedelta


class ConnectionCorrelator:
    """
    Correlates events from multiple log files to create complete connection events.
    Handles the "split metadata" problem where ID and IP are in different files.
    """

    def __init__(self, callback, time_window=10, log_func=None):
        """
        Initialize the correlator.

        Args:
            callback: Function to call with complete connection events
            time_window: Seconds to wait for matching events (default: 10)
            log_func: Optional logging function
        """
        self._callback = callback
        self._time_window = time_window
        self._log = log_func if log_func else lambda msg: None

        # Waiting rooms for unpaired events
        self._waiting_ids = []  # [(anydesk_id, timestamp, data), ...]
        self._waiting_ips = []  # [(ip_address, timestamp, data), ...]

        # Lock for thread-safe access
        self._lock = threading.Lock()

        # Cleanup thread
        self._cleanup_thread = None
        self._running = False
        self._stop_event = threading.Event()

    def add_event(self, event_type, data):
        """
        Add a new event from the log monitor.

        Args:
            event_type: Type of event ('incoming_id', 'incoming_ip', 'outgoing_rejected', 'outgoing_accepted')
            data: Event data dictionary
        """
        if event_type == "incoming_id":
            self._handle_incoming_id(data)
        elif event_type == "incoming_ip":
            self._handle_incoming_ip(data)
        elif event_type == "outgoing_rejected":
            self._handle_outgoing_rejected(data)
        elif event_type == "outgoing_accepted":
            self._handle_outgoing_accepted(data)

    def _handle_incoming_id(self, data):
        """Handle incoming connection ID event"""
        anydesk_id = data["anydesk_id"]
        timestamp = data["timestamp"]  # Now a datetime object

        if not isinstance(timestamp, datetime):
            self._log(f"[CORRELATOR] Invalid timestamp type: {type(timestamp)}")
            return

        self._log(f"[CORRELATOR] New incoming ID: {anydesk_id} at {timestamp}")

        with self._lock:
            # Check if we have a matching IP in waiting room
            match_found = False
            for i, (ip_address, ip_timestamp, ip_data) in enumerate(self._waiting_ips):
                time_diff = abs((timestamp - ip_timestamp).total_seconds())

                if time_diff <= self._time_window:
                    # Match found!
                    self._log(f"[CORRELATOR] Match found: {anydesk_id} <-> {ip_address} (Δ{time_diff:.1f}s)")

                    # Remove from waiting room
                    del self._waiting_ips[i]

                    # Emit complete event
                    self._emit_incoming_request(anydesk_id, ip_address, timestamp)
                    match_found = True
                    break

            if not match_found:
                # No match yet, add to waiting room
                self._waiting_ids.append((anydesk_id, timestamp, data))
                self._log(f"[CORRELATOR] ID added to waiting room (total: {len(self._waiting_ids)})")

    def _handle_incoming_ip(self, data):
        """Handle incoming connection IP event"""
        ip_address = data["ip_address"]
        timestamp = data["timestamp"]  # Now a datetime object

        if not isinstance(timestamp, datetime):
            self._log(f"[CORRELATOR] Invalid timestamp type: {type(timestamp)}")
            return

        self._log(f"[CORRELATOR] New incoming IP: {ip_address} at {timestamp}")

        with self._lock:
            # Check if we have a matching ID in waiting room
            match_found = False
            for i, (anydesk_id, id_timestamp, id_data) in enumerate(self._waiting_ids):
                time_diff = abs((timestamp - id_timestamp).total_seconds())

                if time_diff <= self._time_window:
                    # Match found!
                    self._log(f"[CORRELATOR] Match found: {anydesk_id} <-> {ip_address} (Δ{time_diff:.1f}s)")

                    # Remove from waiting room
                    del self._waiting_ids[i]

                    # Emit complete event
                    self._emit_incoming_request(anydesk_id, ip_address, id_timestamp)
                    match_found = True
                    break

            if not match_found:
                # No match yet, add to waiting room
                self._waiting_ips.append((ip_address, timestamp, data))
                self._log(f"[CORRELATOR] IP added to waiting room (total: {len(self._waiting_ips)})")

    def _handle_outgoing_rejected(self, data):
        """Handle outgoing connection rejection event"""
        anydesk_id = data["anydesk_id"]
        timestamp = data["timestamp"]  # Now a datetime object

        self._log(f"[CORRELATOR] Outgoing rejection: {anydesk_id}")

        # Emit rejection event immediately (no correlation needed)
        event = {
            "event_type": "outgoing_rejected",
            "anydesk_id": anydesk_id,
            "ip_address": None,  # Not available for rejections
            "timestamp": timestamp,
            "metadata": {},
        }
        self._callback(event)

    def _handle_outgoing_accepted(self, data):
        """Handle outgoing connection acceptance event"""
        anydesk_id = data["anydesk_id"]
        timestamp = data["timestamp"]  # Now a datetime object

        self._log(f"[CORRELATOR] Outgoing accepted: {anydesk_id}")

        # Emit acceptance event immediately (no correlation needed)
        event = {
            "event_type": "outgoing_accepted",
            "anydesk_id": anydesk_id,
            "ip_address": None,  # Not available for outgoing
            "timestamp": timestamp,
            "metadata": {},
        }
        self._callback(event)

    def _emit_incoming_request(self, anydesk_id, ip_address, timestamp):
        """
        Emit a complete incoming request event.
        This fires when we have both the ID and IP address.
        """
        event = {
            "event_type": "incoming_request",
            "anydesk_id": anydesk_id,
            "ip_address": ip_address,
            "timestamp": timestamp,
            "metadata": {},
        }
        self._callback(event)

    def start(self):
        """Start the cleanup thread"""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="CorrelatorCleanup")
        self._cleanup_thread.start()
        self._log("[CORRELATOR] Cleanup thread started")

    def stop(self):
        """Stop the cleanup thread"""
        if not self._running:
            return

        self._log("[CORRELATOR] Stopping correlator...")
        self._running = False
        self._stop_event.set()

        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)

        self._log("[CORRELATOR] Correlator stopped")

    def _cleanup_loop(self):
        """
        Periodically clean up old events from waiting rooms.
        Remove events older than 30 seconds.
        """
        while not self._stop_event.is_set():
            time.sleep(10)  # Check every 10 seconds

            with self._lock:
                now = datetime.now()
                max_age = 30  # seconds

                # Clean up old IDs
                self._waiting_ids = [
                    (aid, ts, data) for aid, ts, data in self._waiting_ids if (now - ts).total_seconds() < max_age
                ]

                # Clean up old IPs
                self._waiting_ips = [
                    (ip, ts, data) for ip, ts, data in self._waiting_ips if (now - ts).total_seconds() < max_age
                ]

    def get_stats(self):
        """Get statistics about waiting rooms"""
        with self._lock:
            return {"waiting_ids": len(self._waiting_ids), "waiting_ips": len(self._waiting_ips)}
