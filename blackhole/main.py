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
import sys
import time

from utils.config import DEFAULT_FIREWALL_STATE, TOGGLE_HOTKEY, DRIVER_ERROR_HOTKEY, DRIVER_DOWNLOAD_URL
from utils.gatekeeper import InputGatekeeper
from utils.process_monitor import ProcessMonitor
from utils.api_hooker import APIHooker
from utils.hotkeys import HotkeyListener
from utils.notifications import show_notification, show_driver_error


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
    Create a logging function based on dev mode.

    Args:
        dev_mode: If True, log to console; if False, silent

    Returns:
        Logging function
    """
    if dev_mode:

        def log(msg):
            print(msg)

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

        # Initialize components
        self.gatekeeper = InputGatekeeper(log_func=self.log)
        self.process_monitor = ProcessMonitor(log_func=self.log, callback=self._on_process_event)
        self.api_hooker = APIHooker(log_func=self.log)
        self.hotkey_listener = HotkeyListener(TOGGLE_HOTKEY, self.toggle_firewall, log_func=self.log)
        self.driver_error_listener = HotkeyListener(DRIVER_ERROR_HOTKEY, self.show_fake_driver_error, log_func=self.log)

        self.log("\n" + "=" * 60)
        self.log("  Task Host Windows Service")
        self.log("=" * 60)
        self.log(f"Mode: {'DEV' if dev_mode else 'PRODUCTION'}")
        self.log(f"Architecture: API Hooking + Low-Level Hooks")
        self.log(f"Default state: {'ACTIVE' if DEFAULT_FIREWALL_STATE else 'INACTIVE'}")
        self.log(f"Hotkey: Command+Shift+F (toggle firewall)")
        self.log(f"Hotkey: Command+Shift+G (fake driver error)")
        self.log("=" * 60 + "\n")

    def _on_process_event(self, event_type, pid, process_name):
        """
        Handle process found/lost events from ProcessMonitor.

        Args:
            event_type: 'found' or 'lost'
            pid: Process ID
            process_name: Name of the process
        """
        if event_type == "found":
            # Hook the process
            success = self.api_hooker.hook_process(pid, process_name)
            if not success:
                self.log(f"[SERVICE] WARNING: Failed to hook {process_name} (PID: {pid})")
        elif event_type == "lost":
            # Unhook the process
            self.api_hooker.unhook_process(pid)

    def show_fake_driver_error(self):
        """Show fake driver error popup (called by Command+Shift+G hotkey)"""
        self.log("[SERVICE] Fake driver error triggered - showing popup to scammer...")
        show_driver_error(DRIVER_DOWNLOAD_URL)
        self.log(f"[SERVICE] Driver download URL displayed: {DRIVER_DOWNLOAD_URL}")

    def toggle_firewall(self):
        """Toggle firewall on/off (called by hotkey)"""
        if self.firewall_active:
            # Turn OFF
            self.log("[SERVICE] Hotkey pressed - DISABLING firewall...")
            self.gatekeeper.stop()
            self.firewall_active = False
            self.log("[SERVICE] Firewall is now INACTIVE - all input allowed")

            if self.dev_mode:
                show_notification(title="Blackhole Firewall", message="Firewall DISABLED\nRemote input is now ALLOWED")
        else:
            # Turn ON
            self.log("[SERVICE] Hotkey pressed - ENABLING firewall...")
            self.gatekeeper.start()

            if self.gatekeeper.is_active():
                self.firewall_active = True
                self.log("[SERVICE] Firewall is now ACTIVE - blocking tagged input")

                if self.dev_mode:
                    show_notification(
                        title="Blackhole Firewall", message="Firewall ENABLED\nBlocking remote desktop input"
                    )
            else:
                self.log("[SERVICE] Firewall activation FAILED")

                if self.dev_mode:
                    show_notification(title="Blackhole Firewall", message="ERROR: Failed to activate firewall")

    def start(self):
        """Start the service"""
        self.log("[SERVICE] Starting Blackhole service...")

        # Start process monitor first
        self.process_monitor.start()

        # Start hotkey listeners
        self.hotkey_listener.start()
        self.driver_error_listener.start()
        self.log("[SERVICE] Hotkey listeners active")

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
                # DEV MODE: Auto-shutdown after 60 seconds to prevent lockouts
                self.log("[DEV MODE] Auto-shutdown enabled: service will stop in 60 seconds")
                countdown = 60
                while countdown > 0:
                    time.sleep(1)
                    countdown -= 1
                    if countdown in [30, 10, 5, 4, 3, 2, 1]:
                        self.log(f"[DEV MODE] Auto-shutdown in {countdown} second(s)...")
                self.log("\n[DEV MODE] Auto-shutdown triggered after 60 seconds")
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

                self.log("\n" + "=" * 60)
                self.log("  Session Statistics")
                self.log("=" * 60)
                self.log(f"Blocked keyboard:  {stats.get('blocked_keys', 0)}")
                self.log(f"Blocked mouse:     {stats.get('blocked_mouse', 0)}")
                self.log(f"Allowed keyboard:  {stats.get('allowed_keys', 0)}")
                self.log(f"Allowed mouse:     {stats.get('allowed_mouse', 0)}")
                self.log(f"Hooked processes:  {len(hooked_pids)}")
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
