#!/usr/bin/env python3
"""
Blackhole Input Firewall Service
Selectively blocks remote desktop input while allowing host input.
Control via Command+Shift+F hotkey (no network connection required).
"""

import os
import sys
import time

from utils.config import DEFAULT_FIREWALL_STATE
from utils.gatekeeper import InputGatekeeper


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

        self.log("\n" + "=" * 60)
        self.log("  Blackhole Input Firewall Service")
        self.log("=" * 60)
        self.log(f"Mode: {'DEV' if dev_mode else 'PRODUCTION'}")
        self.log(f"Control: Service start/stop (no hotkey)")
        self.log(f"Default state: {'ACTIVE' if DEFAULT_FIREWALL_STATE else 'INACTIVE'}")
        self.log("=" * 60 + "\n")

    def start(self):
        """Start the service"""
        self.log("[SERVICE] Starting Blackhole service...")

        # Apply default state (always ACTIVE now)
        if DEFAULT_FIREWALL_STATE:
            self.log("[SERVICE] Activating firewall...")
            self.gatekeeper.start()

            # Check if activation succeeded
            if self.gatekeeper.is_active():
                self.firewall_active = True
                self.log("[SERVICE] Firewall is ACTIVE - remote input will be blocked")
            else:
                self.firewall_active = False
                self.log("[SERVICE] Firewall activation FAILED (fail-safe triggered)")
                self.log("[SERVICE] No whitelisted devices found - check HYPERVISOR_IDENTIFIERS")
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

        # Stop firewall if active
        if self.firewall_active:
            self.gatekeeper.stop()

        # Print statistics in dev mode
        if self.dev_mode:
            try:
                stats = self.gatekeeper.get_stats()
                self.log("\n" + "=" * 60)
                self.log("  Session Statistics")
                self.log("=" * 60)
                self.log(f"Blocked keyboard:  {stats.get('blocked_keys', 0)}")
                self.log(f"Blocked mouse:     {stats.get('blocked_mouse', 0)}")
                self.log(f"Allowed keyboard:  {stats.get('allowed_keys', 0)}")
                self.log(f"Allowed mouse:     {stats.get('allowed_mouse', 0)}")
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
