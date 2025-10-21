"""
Hotkey detection for global keyboard shortcuts
"""

import threading
from pynput import keyboard


class HotkeyListener:
    """
    Listens for a specific hotkey combination and triggers a callback.
    Suppresses the hotkey so it doesn't pass through to applications.
    """

    def __init__(self, hotkey_set, callback, log_func=None):
        """
        Initialize the hotkey listener.

        Args:
            hotkey_set: Set of keys that must be pressed simultaneously (e.g., {Key.cmd_l, Key.shift, 'f'})
            callback: Function to call when hotkey is detected
            log_func: Optional logging function (for dev mode)
        """
        self.hotkey_set = hotkey_set
        self.callback = callback
        self._log = log_func if log_func else lambda msg: None

        # Track currently pressed keys
        self._current_keys = set()

        # Flag to prevent multiple triggers while keys are held
        self._hotkey_triggered = False

        # Listener instance
        self._listener = None

    def _on_press(self, key):
        """
        Callback for key press events.
        Checks if the hotkey combination is complete.
        """
        # Normalize key representation
        try:
            # For character keys, use the char
            if hasattr(key, "char") and key.char is not None:
                normalized_key = key.char.lower()
            else:
                # For special keys, use the key object itself
                normalized_key = key
        except AttributeError:
            normalized_key = key

        # Debug: Log all key presses
        self._log(f"[HOTKEY DEBUG] Key pressed: {key} → normalized: {normalized_key}")
        self._log(f"[HOTKEY DEBUG] Current keys: {self._current_keys}")
        self._log(f"[HOTKEY DEBUG] Expected hotkey: {self._normalize_hotkey_set()}")

        # Add to current keys
        self._current_keys.add(normalized_key)

        # Check if hotkey is complete
        if self._is_hotkey_pressed() and not self._hotkey_triggered:
            self._hotkey_triggered = True
            self._log(f"[HOTKEY] Detected: {self.hotkey_set}")

            # Trigger callback in separate thread to avoid blocking
            threading.Thread(target=self.callback, daemon=True).start()

            # Suppress the hotkey (don't pass through to apps)
            return False

    def _on_release(self, key):
        """
        Callback for key release events.
        Removes key from current set and resets trigger flag.
        """
        # Normalize key representation
        try:
            if hasattr(key, "char") and key.char is not None:
                normalized_key = key.char.lower()
            else:
                normalized_key = key
        except AttributeError:
            normalized_key = key

        # Remove from current keys
        self._current_keys.discard(normalized_key)

        # Reset trigger flag when any hotkey key is released
        if normalized_key in self._normalize_hotkey_set():
            self._hotkey_triggered = False

    def _normalize_hotkey_set(self):
        """
        Normalize the hotkey set for comparison.
        Converts character keys to lowercase.
        """
        normalized = set()
        for key in self.hotkey_set:
            if isinstance(key, str):
                normalized.add(key.lower())
            else:
                normalized.add(key)
        return normalized

    def _is_hotkey_pressed(self):
        """
        Check if all keys in the hotkey set are currently pressed.
        """
        normalized_hotkey = self._normalize_hotkey_set()
        return normalized_hotkey.issubset(self._current_keys)

    def start(self):
        """Start listening for the hotkey"""
        if self._listener is not None:
            self._log("[WARNING] Hotkey listener already running")
            return

        self._log(f"[HOTKEY] Listening for: {self.hotkey_set}")

        try:
            # Create and start listener
            self._listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
            self._listener.start()

            # Wait for listener to be ready (ensures hook is installed and message loop is running)
            self._listener.wait()

            self._log(f"[HOTKEY] Listener ready (running={self._listener.running})")

            if not self._listener.running:
                self._log("[ERROR] Listener started but is not running - hook installation may have failed")

        except Exception as e:
            self._log(f"[ERROR] Failed to start hotkey listener: {e}")
            self._log("[ERROR] This may be due to insufficient permissions (need Administrator)")
            self._listener = None

    def stop(self):
        """Stop listening for the hotkey"""
        if self._listener is None:
            return

        self._log("[HOTKEY] Stopping listener")
        self._listener.stop()
        self._listener = None
        self._current_keys.clear()
        self._hotkey_triggered = False

    def join(self):
        """Wait for the listener thread to finish"""
        if self._listener is not None:
            self._listener.join()
