"""
Connection Correlator - Matches split metadata from AnyDesk log files
Uses sequential matching: ID is always followed by IP on the next line
"""

from datetime import datetime


class ConnectionCorrelator:
    """
    Correlates events from AnyDesk trace files to create complete connection events.
    Uses simple sequential matching: ID logged first, IP logged immediately after.
    """

    def __init__(self, callback, mode="portable", log_func=None):
        """
        Initialize the correlator.

        Args:
            callback: Function to call with complete connection events
            mode: "service" or "portable"
            log_func: Optional logging function
        """
        self._callback = callback
        self._mode = mode
        self._log = log_func if log_func else lambda msg: None

        # Sequential matching: just track the most recent pending ID
        self._pending_id = None
        self._pending_timestamp = None

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
        """
        Handle incoming connection ID event.
        Store as pending, wait for next IP to arrive.
        """
        anydesk_id = data["anydesk_id"]
        timestamp = data["timestamp"]

        if not isinstance(timestamp, datetime):
            self._log(f"[CORRELATOR] Invalid timestamp type: {type(timestamp)}")
            return

        self._log(f"[CORRELATOR] New incoming ID: {anydesk_id} at {timestamp}")

        if self._mode == "portable":
            # PORTABLE MODE: Fire immediately, IP is not logged
            self._log("[CORRELATOR] Portable mode: Firing event with ID only.")
            self._emit_incoming_request(anydesk_id, None, timestamp)
            return

        # SERVICE MODE: Store as pending, next IP event will match it
        self._log("[CORRELATOR] Service mode: Storing pending ID, waiting for IP.")
        self._pending_id = anydesk_id
        self._pending_timestamp = timestamp

    def _handle_incoming_ip(self, data):
        """
        Handle incoming connection IP event.
        Match with most recent pending ID and fire immediately.
        """
        ip_address = data["ip_address"]
        timestamp = data["timestamp"]

        if not isinstance(timestamp, datetime):
            self._log(f"[CORRELATOR] Invalid timestamp type: {type(timestamp)}")
            return

        self._log(f"[CORRELATOR] New incoming IP: {ip_address} at {timestamp}")

        # Match with pending ID (should always exist since ID is logged first)
        if self._pending_id:
            self._log(f"[CORRELATOR] Match found: {self._pending_id} <-> {ip_address}")
            # Fire the reverse connection!
            self._emit_incoming_request(self._pending_id, ip_address, self._pending_timestamp)
            # Clear pending for next connection
            self._pending_id = None
            self._pending_timestamp = None
        else:
            # This should never happen (ID always logged before IP)
            self._log(f"[CORRELATOR] WARNING: IP received without pending ID! This should not happen.")

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
        """Start the correlator (no-op for compatibility)"""
        self._log("[CORRELATOR] Correlator started (sequential mode)")

    def stop(self):
        """Stop the correlator (no-op for compatibility)"""
        self._log("[CORRELATOR] Correlator stopped")

    def get_stats(self):
        """Get statistics (simplified for sequential mode)"""
        return {
            "waiting_ids": 1 if self._pending_id else 0,
            "waiting_ips": 0,  # No longer used in sequential mode
        }
