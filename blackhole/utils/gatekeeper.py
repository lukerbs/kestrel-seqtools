# utils/gatekeeper.py
"""
Input Gatekeeper - Selective blocking of remote desktop input.
Uses pynput's 'injected' flag to detect and block programmatically injected input.
"""

from pynput import keyboard, mouse


class InputGatekeeper:
    """
    Blocks remote desktop input by detecting the 'injected' flag.
    Remote desktop tools (AnyDesk, TeamViewer) inject input programmatically,
    while your physical input is not marked as injected.
    """

    def __init__(self, log_func=None):
        self._log = log_func if log_func else lambda msg: None
        self._log("[GATEKEEPER] Initializing...")

        # Listeners
        self._kbd_listener = None
        self._mouse_listener = None
        self._active = False

        # Statistics
        self.stats = {
            "blocked_keys": 0,
            "blocked_mouse": 0,
            "allowed_keys": 0,
            "allowed_mouse": 0,
        }

    def _on_press(self, key, injected):
        """Keyboard press callback"""
        if injected:
            # Injected input - block it (remote desktop tool)
            self.stats["blocked_keys"] += 1
            self._log(f"[BLOCKED] Keyboard: {key} (injected)")
            return False  # Block the event
        else:
            # Real hardware input - allow it
            self.stats["allowed_keys"] += 1
            # Don't log every allowed event (too spammy)

    def _on_release(self, key, injected):
        """Keyboard release callback"""
        if injected:
            return False  # Block the event

    def _on_click(self, x, y, button, pressed, injected):
        """Mouse click callback"""
        if injected:
            # Injected input - block it
            if pressed:
                self.stats["blocked_mouse"] += 1
                self._log(f"[BLOCKED] Mouse click at ({x}, {y}) (injected)")
            return False  # Block the event
        else:
            # Real hardware input - allow it
            if pressed:
                self.stats["allowed_mouse"] += 1

    def _on_move(self, x, y, injected):
        """Mouse move callback"""
        if injected:
            return False  # Block the event silently (too spammy to log)

    def _on_scroll(self, x, y, dx, dy, injected):
        """Mouse scroll callback"""
        if injected:
            return False  # Block the event

    def start(self):
        """Activate selective input blocking"""
        if self._active:
            self._log("[WARNING] Gatekeeper already active")
            return

        self._log("[GATEKEEPER] Starting input firewall...")

        # Create listeners with suppress=True to block events
        self._kbd_listener = keyboard.Listener(
            on_press=self._on_press, on_release=self._on_release, suppress=True  # Critical: allows us to block events
        )

        self._mouse_listener = mouse.Listener(
            on_click=self._on_click,
            on_move=self._on_move,
            on_scroll=self._on_scroll,
            suppress=True,  # Critical: allows us to block events
        )

        # Start listeners
        self._kbd_listener.start()
        self._mouse_listener.start()

        self._active = True
        self._log("[GATEKEEPER] Input firewall ACTIVE - blocking injected input")

    def stop(self):
        """Deactivate and restore all input"""
        if not self._active:
            return

        self._log("[GATEKEEPER] Stopping input firewall...")

        if self._kbd_listener:
            self._kbd_listener.stop()
        if self._mouse_listener:
            self._mouse_listener.stop()

        self._active = False
        self._log("[GATEKEEPER] Input firewall INACTIVE")

    def is_active(self):
        """Check if firewall is currently active"""
        return self._active

    def get_stats(self):
        """Get statistics"""
        return self.stats.copy()
