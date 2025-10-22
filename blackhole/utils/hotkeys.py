"""
Hotkey Listener - Detects global hotkey combinations
"""

import threading
from pynput import keyboard


class HotkeyListener:
    """
    Listens for a global hotkey combination and triggers a callback.
    """

    def __init__(self, hotkey_combo, callback, log_func=None):
        """
        Initialize the hotkey listener.

        Args:
            hotkey_combo: Set of keys that must be pressed (e.g., {Key.ctrl, Key.shift, 'f'})
            callback: Function to call when hotkey is detected
            log_func: Optional logging function
        """
        self._log = log_func if log_func else lambda msg: None
        self._hotkey_combo = hotkey_combo
        self._callback = callback
        self._listener = None
        self._current_keys = set()

    def start(self):
        """Start listening for the hotkey"""
        self._log(f"[HOTKEY] Starting listener for: {self._format_hotkey()}")
        self._listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
        self._listener.start()

    def stop(self):
        """Stop listening for the hotkey"""
        if self._listener:
            self._listener.stop()
            self._log("[HOTKEY] Listener stopped")

    def _on_press(self, key):
        """Handle key press events"""
        # Normalize the key
        try:
            normalized_key = key.char if hasattr(key, "char") else key
        except AttributeError:
            normalized_key = key

        # Add to current keys
        self._current_keys.add(normalized_key)

        # Check if hotkey combo is pressed
        if self._is_hotkey_pressed():
            self._log(f"[HOTKEY] Detected: {self._format_hotkey()}")
            # Call the callback in a separate thread to avoid blocking
            threading.Thread(target=self._callback, daemon=True).start()

    def _on_release(self, key):
        """Handle key release events"""
        # Normalize the key
        try:
            normalized_key = key.char if hasattr(key, "char") else key
        except AttributeError:
            normalized_key = key

        # Remove from current keys
        self._current_keys.discard(normalized_key)

    def _is_hotkey_pressed(self):
        """Check if the hotkey combination is currently pressed"""
        return self._hotkey_combo.issubset(self._current_keys)

    def _format_hotkey(self):
        """Format the hotkey combo for display"""
        keys = []
        for key in self._hotkey_combo:
            if isinstance(key, str):
                keys.append(key.upper())
            else:
                keys.append(str(key).replace("Key.", ""))
        return "+".join(keys)
