"""
Input Gatekeeper - Blocks or scrambles tagged input using low-level hooks
Uses ctypes to install WH_KEYBOARD_LL and WH_MOUSE_LL hooks that check dwExtraInfo
"""

import ctypes
from ctypes import wintypes
import threading

from .config import MAGIC_TAG, FIREWALL_MODE_OFF, FIREWALL_MODE_BLOCK, FIREWALL_MODE_CHAOS
from .key_scrambler import KeyScrambler
from .win32_api import (
    user32,
    kernel32,
    HOOKPROC,
    KBDLLHOOKSTRUCT,
    MSLLHOOKSTRUCT,
    WH_KEYBOARD_LL,
    WH_MOUSE_LL,
    HC_ACTION,
    MSG,
    WPARAM,
    LPARAM,
    INPUT,
    INPUT_UNION,
    KEYBDINPUT,
    MOUSEINPUT,
    INPUT_KEYBOARD,
    INPUT_MOUSE,
    KEYEVENTF_KEYUP,
    MOUSEEVENTF_MOVE,
    MOUSEEVENTF_ABSOLUTE,
    SM_CXSCREEN,
    SM_CYSCREEN,
    WM_KEYUP,
    WM_SYSKEYUP,
)


class InputGatekeeper:
    """
    Blocks or scrambles input tagged by API hooker using low-level Windows hooks.
    Checks dwExtraInfo field in hook callbacks to detect tagged input.
    Supports three modes: OFF, BLOCK, CHAOS
    """

    def __init__(self, log_func=None, mode=FIREWALL_MODE_OFF):
        """
        Initialize the gatekeeper.

        Args:
            log_func: Optional logging function
            mode: Firewall mode (OFF, BLOCK, or CHAOS)
        """
        self._log = log_func if log_func else lambda msg: None
        self._log("[GATEKEEPER] Initializing ctypes-based hooks...")

        # Firewall mode
        self._mode = mode
        self._mode_lock = threading.Lock()

        # Hook handles
        self._kbd_hook = None
        self._mouse_hook = None

        # Hook callback references (must keep these alive to prevent GC)
        self._kbd_callback_ref = None
        self._mouse_callback_ref = None

        # Message loop thread
        self._hook_thread = None
        self._hook_thread_id = None  # Store the hook thread's ID for clean shutdown
        self._active = False
        self._stop_event = threading.Event()

        # Chaos mode components
        self._key_scrambler = KeyScrambler()
        self._screen_width = user32.GetSystemMetrics(SM_CXSCREEN)
        self._screen_height = user32.GetSystemMetrics(SM_CYSCREEN)

        # Statistics
        self.stats = {
            "blocked_keys": 0,
            "blocked_mouse": 0,
            "scrambled_keys": 0,
            "inverted_mouse": 0,
            "allowed_keys": 0,
            "allowed_mouse": 0,
        }

    def _keyboard_hook_callback(self, nCode, wParam, lParam):
        """
        Low-level keyboard hook callback.
        Checks dwExtraInfo for MAGIC_TAG and blocks/scrambles based on mode.
        """
        if nCode == HC_ACTION:
            try:
                # Cast lParam to KBDLLHOOKSTRUCT pointer
                kbd_struct_ptr = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT))
                kbd_struct = kbd_struct_ptr.contents

                # Check if dwExtraInfo contains our magic tag
                if kbd_struct.dwExtraInfo == MAGIC_TAG:
                    # This is tagged input from hooked process
                    with self._mode_lock:
                        current_mode = self._mode

                    if current_mode == FIREWALL_MODE_BLOCK:
                        # BLOCK mode - just block it
                        self.stats["blocked_keys"] += 1
                        self._log(f"[BLOCKED] Keyboard event (tagged)")
                        return 1  # Non-zero blocks the event

                    elif current_mode == FIREWALL_MODE_CHAOS:
                        # CHAOS mode - scramble and re-inject
                        vk_code = kbd_struct.vkCode
                        is_keyup = wParam == WM_KEYUP or wParam == WM_SYSKEYUP

                        # Only scramble alphanumeric keys
                        if self._key_scrambler.is_scrambleable(vk_code):
                            scrambled_vk = self._key_scrambler.scramble_key(vk_code)
                            self._inject_keyboard(scrambled_vk, is_keyup)
                            self.stats["scrambled_keys"] += 1
                            return 1  # Block original, we injected scrambled version
                        else:
                            # Not alphanumeric, just block it
                            self.stats["blocked_keys"] += 1
                            return 1

                # Not tagged - allow it (Mac/QEMU input)
                self.stats["allowed_keys"] += 1

            except Exception as e:
                self._log(f"[GATEKEEPER] Error in keyboard callback: {e}")

        # Pass to next hook in chain
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    def _mouse_hook_callback(self, nCode, wParam, lParam):
        """
        Low-level mouse hook callback.
        Checks dwExtraInfo for MAGIC_TAG and blocks/inverts based on mode.
        """
        if nCode == HC_ACTION:
            try:
                # Cast lParam to MSLLHOOKSTRUCT pointer
                mouse_struct_ptr = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT))
                mouse_struct = mouse_struct_ptr.contents

                # Check if dwExtraInfo contains our magic tag
                if mouse_struct.dwExtraInfo == MAGIC_TAG:
                    # This is tagged input from hooked process
                    with self._mode_lock:
                        current_mode = self._mode

                    if current_mode == FIREWALL_MODE_BLOCK:
                        # BLOCK mode - just block it
                        self.stats["blocked_mouse"] += 1
                        # Only log clicks, not moves (too spammy)
                        if wParam in [0x0201, 0x0204, 0x0207]:  # Button down events
                            self._log(f"[BLOCKED] Mouse event (tagged)")
                        return 1  # Non-zero blocks the event

                    elif current_mode == FIREWALL_MODE_CHAOS:
                        # CHAOS mode - invert and re-inject (only for moves)
                        if wParam == 0x0200:  # WM_MOUSEMOVE
                            x = mouse_struct.pt.x
                            y = mouse_struct.pt.y

                            # Invert coordinates
                            inverted_x = self._screen_width - x
                            inverted_y = self._screen_height - y

                            self._inject_mouse(inverted_x, inverted_y)
                            self.stats["inverted_mouse"] += 1
                            return 1  # Block original, we injected inverted version
                        else:
                            # For clicks/scrolls, just block them
                            self.stats["blocked_mouse"] += 1
                            return 1

                # Not tagged - allow it (Mac/QEMU input)
                self.stats["allowed_mouse"] += 1

            except Exception as e:
                self._log(f"[GATEKEEPER] Error in mouse callback: {e}")

        # Pass to next hook in chain
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    def _hook_thread_func(self):
        """
        Thread function that installs hooks and runs message loop.
        This must run in its own thread to process hook messages.
        """
        # Store this thread's ID for clean shutdown
        self._hook_thread_id = kernel32.GetCurrentThreadId()

        try:
            self._log("[GATEKEEPER] Hook thread started")

            # Get module handle
            hInstance = kernel32.GetModuleHandleW(None)

            # Create callback references (prevent garbage collection)
            self._kbd_callback_ref = HOOKPROC(self._keyboard_hook_callback)
            self._mouse_callback_ref = HOOKPROC(self._mouse_hook_callback)

            # Install hooks
            self._kbd_hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._kbd_callback_ref, hInstance, 0)

            self._mouse_hook = user32.SetWindowsHookExW(WH_MOUSE_LL, self._mouse_callback_ref, hInstance, 0)

            if not self._kbd_hook or not self._mouse_hook:
                error_code = kernel32.GetLastError()
                self._log(f"[GATEKEEPER] ERROR: Failed to install hooks. Error code: {error_code}")
                return

            self._log("[GATEKEEPER] Hooks installed successfully")
            self._log("[GATEKEEPER] Input firewall ACTIVE - blocking tagged input")

            # Run message loop
            msg = MSG()
            while not self._stop_event.is_set():
                # Non-blocking message check
                if user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):  # PM_REMOVE = 1
                    if msg.message == 0x0012:  # WM_QUIT
                        break
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                else:
                    # No message, sleep briefly to avoid busy-wait
                    self._stop_event.wait(0.01)

            self._log("[GATEKEEPER] Message loop exited")

        except Exception as e:
            self._log(f"[GATEKEEPER] Error in hook thread: {e}")

        finally:
            # Cleanup hooks
            if self._kbd_hook:
                user32.UnhookWindowsHookEx(self._kbd_hook)
                self._kbd_hook = None

            if self._mouse_hook:
                user32.UnhookWindowsHookEx(self._mouse_hook)
                self._mouse_hook = None

            self._log("[GATEKEEPER] Hooks uninstalled")

    def _inject_keyboard(self, vk_code, is_keyup):
        """
        Inject a keyboard event using SendInput.

        Args:
            vk_code: Virtual key code to inject
            is_keyup: True for key release, False for key press
        """
        try:
            # Create INPUT structure
            inp = INPUT()
            inp.type = INPUT_KEYBOARD
            inp.union.ki = KEYBDINPUT()
            inp.union.ki.wVk = vk_code
            inp.union.ki.wScan = 0
            inp.union.ki.dwFlags = KEYEVENTF_KEYUP if is_keyup else 0
            inp.union.ki.time = 0
            inp.union.ki.dwExtraInfo = 0  # No tag - this is our injected input

            # Send the input
            user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

        except Exception as e:
            self._log(f"[GATEKEEPER] Error injecting keyboard: {e}")

    def _inject_mouse(self, x, y):
        """
        Inject a mouse move event using SendInput.

        Args:
            x: X coordinate (absolute)
            y: Y coordinate (absolute)
        """
        try:
            # Convert to normalized absolute coordinates (0-65535)
            normalized_x = int((x * 65535) / self._screen_width)
            normalized_y = int((y * 65535) / self._screen_height)

            # Create INPUT structure
            inp = INPUT()
            inp.type = INPUT_MOUSE
            inp.union.mi = MOUSEINPUT()
            inp.union.mi.dx = normalized_x
            inp.union.mi.dy = normalized_y
            inp.union.mi.mouseData = 0
            inp.union.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
            inp.union.mi.time = 0
            inp.union.mi.dwExtraInfo = 0  # No tag - this is our injected input

            # Send the input
            user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

        except Exception as e:
            self._log(f"[GATEKEEPER] Error injecting mouse: {e}")

    def set_mode(self, mode):
        """
        Set the firewall mode.

        Args:
            mode: FIREWALL_MODE_OFF, FIREWALL_MODE_BLOCK, or FIREWALL_MODE_CHAOS
        """
        with self._mode_lock:
            old_mode = self._mode
            self._mode = mode
            self._log(f"[GATEKEEPER] Mode changed: {old_mode} -> {mode}")

    def get_mode(self):
        """Get the current firewall mode"""
        with self._mode_lock:
            return self._mode

    def start(self):
        """Activate selective input blocking"""
        if self._active:
            self._log("[WARNING] Gatekeeper already active")
            return

        self._log("[GATEKEEPER] Starting input firewall...")
        self._active = True
        self._stop_event.clear()

        # Start hook thread
        self._hook_thread = threading.Thread(target=self._hook_thread_func, daemon=True, name="GatekeeperHooks")
        self._hook_thread.start()

        # Give hooks time to install
        import time

        time.sleep(0.2)

    def stop(self):
        """Deactivate and restore all input"""
        if not self._active:
            return

        self._log("[GATEKEEPER] Stopping input firewall...")
        self._active = False

        # Signal hook thread to stop
        self._stop_event.set()

        # Post WM_QUIT to the correct hook thread (not the calling thread)
        if self._hook_thread and self._hook_thread.is_alive() and self._hook_thread_id:
            user32.PostThreadMessageW(self._hook_thread_id, 0x0012, 0, 0)  # WM_QUIT

        # Wait for hook thread to finish
        if self._hook_thread:
            self._hook_thread.join(timeout=2)

        self._log("[GATEKEEPER] Input firewall INACTIVE")

    def is_active(self):
        """Check if firewall is currently active"""
        return self._active

    def get_stats(self):
        """Get statistics"""
        return self.stats.copy()
