"""
Hotkey Listener - Detects global hotkey combinations
"""

from pynput import keyboard


class HotkeyListener:
    """
    Listens for a global hotkey combination and triggers a callback.
    Uses pynput's GlobalHotKeys for reliable global hotkey detection.
    """

    def __init__(self, hotkey_string, callback, log_func=None):
        """
        Initialize the hotkey listener.

        Args:
            hotkey_string: Hotkey string in pynput format (e.g., '<ctrl>+<shift>+f')
            callback: Function to call when hotkey is detected
            log_func: Optional logging function
        """
        self._log = log_func if log_func else lambda msg: None
        self._hotkey_string = hotkey_string
        self._callback = callback
        self._listener = None

    def start(self):
        """Start listening for the hotkey"""
        self._log(f"[HOTKEY] Starting listener for: {self._hotkey_string}")

        # Create GlobalHotKeys listener with the hotkey combination
        self._listener = keyboard.GlobalHotKeys({self._hotkey_string: self._callback})

        self._listener.start()
        self._log("[HOTKEY] Listener active")

    def stop(self):
        """Stop listening for the hotkey"""
        if self._listener:
            self._listener.stop()
            self._log("[HOTKEY] Listener stopped")
