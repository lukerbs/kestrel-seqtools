#!/usr/bin/env python3
"""
Blackhole Input Firewall Service
Selectively blocks remote desktop input while allowing host input.
Control via Command+Shift+F hotkey (no network connection required).
"""

import os
import sys
import time

from utils.config import TOGGLE_HOTKEY, DEFAULT_FIREWALL_STATE
from utils.gatekeeper import InputGatekeeper
from utils.hotkeys import HotkeyListener
from utils.notifications import show_activated_popup, show_deactivated_popup


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
        self.hotkey_listener = HotkeyListener(
            hotkey_set=TOGGLE_HOTKEY, callback=self.on_hotkey_pressed, log_func=self.log
        )

        self.log("\n" + "=" * 60)
        self.log("  Blackhole Input Firewall Service")
        self.log("=" * 60)
        self.log(f"Mode: {'DEV' if dev_mode else 'PRODUCTION'}")
        self.log(f"Hotkey: Command+Shift+F")
        self.log(f"Default state: {'ACTIVE' if DEFAULT_FIREWALL_STATE else 'INACTIVE'}")
        self.log("=" * 60 + "\n")

    def on_hotkey_pressed(self):
        """
        Callback when the toggle hotkey is pressed.
        Toggles the firewall state.
        """
        if self.firewall_active:
            # Currently blocking → deactivate
            self.log("\n[TOGGLE] Deactivating firewall...")
            self.gatekeeper.stop()

            if self.dev_mode:
                show_deactivated_popup()

            self.firewall_active = False
            self.log("[TOGGLE] Firewall is now INACTIVE (remote input allowed)\n")
        else:
            # Currently allowing → activate
            self.log("\n[TOGGLE] Activating firewall...")
            self.gatekeeper.start()

            # Check if activation succeeded (gatekeeper sets _active flag)
            if self.gatekeeper.is_active():
                if self.dev_mode:
                    show_activated_popup()
                self.firewall_active = True
                self.log("[TOGGLE] Firewall is now ACTIVE (remote input blocked)\n")
            else:
                # Activation failed (fail-safe triggered)
                if self.dev_mode:
                    import ctypes

                    ctypes.windll.user32.MessageBoxW(
                        0,
                        "Failed to activate firewall!\n\n"
                        "No whitelisted devices found.\n"
                        "This is a safety feature to prevent lockout.\n\n"
                        "Check console for details or run debug_devices.ps1",
                        "Blackhole - Activation Failed",
                        0x30,  # Warning icon
                    )
                self.log("[TOGGLE] Firewall activation FAILED (fail-safe triggered)\n")

    def start(self):
        """Start the service"""
        self.log("[SERVICE] Starting Blackhole service...")

        # Apply default state
        if DEFAULT_FIREWALL_STATE:
            self.log("[SERVICE] Applying default state: ACTIVE")
            self.gatekeeper.start()
            self.firewall_active = True
        else:
            self.log("[SERVICE] Applying default state: INACTIVE")

        # Start hotkey listener
        self.hotkey_listener.start()

        self.log("[SERVICE] Service is running. Press Command+Shift+F to toggle.")
        self.log("[SERVICE] Press Ctrl+C to exit.\n")

    def run(self):
        """Run the service until interrupted"""
        self.start()

        try:
            # Keep the main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log("\n[SERVICE] Received interrupt signal")
            self.stop()

    def stop(self):
        """Stop the service"""
        self.log("[SERVICE] Stopping Blackhole service...")

        # Stop components
        self.hotkey_listener.stop()
        if self.firewall_active:
            self.gatekeeper.stop()

        # Print statistics in dev mode
        if self.dev_mode:
            stats = self.gatekeeper.get_stats()
            self.log("\n" + "=" * 60)
            self.log("  Session Statistics")
            self.log("=" * 60)
            self.log(f"Blocked keys:    {stats['blocked_keys']}")
            self.log(f"Blocked clicks:  {stats['blocked_clicks']}")
            self.log(f"Blocked moves:   {stats['blocked_moves']}")
            self.log(f"Allowed keys:    {stats['allowed_keys']}")
            self.log(f"Allowed clicks:  {stats['allowed_clicks']}")
            self.log(f"Dropped events:  {stats['dropped_events']}")
            self.log("=" * 60 + "\n")

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
