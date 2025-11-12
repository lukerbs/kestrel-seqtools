#!/usr/bin/env python3
"""
Test script for Layer 2 Screen Blanking Defense (Overlay Neutralization)

This script creates a full-screen topmost overlay window to test Blackhole's
Layer 2 defense mechanism. The overlay should be detected and neutralized
by the OverlayDefender.

SAFEGUARDS:
- 20-second automatic timeout
- Global hotkey (ESC key) - works even when screen is blanked
- Keyboard interrupt (Ctrl+C) handling
- Multiple cleanup attempts
- Try/finally ensures window is always destroyed
- Visual countdown timer
- Emergency cleanup on any error

IMPORTANT: Ensure Blackhole is running before executing this script.
"""

import ctypes
import os
import sys
import time
import threading
from ctypes import wintypes

try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    print("WARNING: pynput not available. Global hotkey (ESC) will not work.")
    print("         Install with: pip install pynput")

# Add parent directory to path to import utils
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.insert(0, parent_dir)

try:
    from utils.win32_api import (
        user32,
        kernel32,
        HINSTANCE,
        wintypes,
        WNDPROC,
        WNDCLASSEXW,
        RECT,
        LRESULT,
        WPARAM,
        LPARAM,
        WS_EX_TOPMOST,
        WM_DESTROY,
        WM_QUIT,
        HWND_NOTOPMOST,
        SWP_NOMOVE,
        SWP_NOSIZE,
        SWP_NOACTIVATE,
    )
except ImportError:
    print("ERROR: Could not import win32_api. Make sure you're running from the blackhole directory.")
    sys.exit(1)

# Additional constants we need
WS_POPUP = 0x80000000
WS_VISIBLE = 0x10000000
SW_SHOW = 5
SW_HIDE = 0
SM_CXSCREEN = 0
SM_CYSCREEN = 1
COLOR_WINDOW = 5
HWND_TOPMOST = -1  # For SetWindowPos

# ============================================================================
# LOCAL WIN32 API FUNCTION DEFINITIONS
# (Functions not in win32_api.py that we need for this test)
# ============================================================================

# GetSystemMetrics - Get screen dimensions
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int

# ShowWindow - Show/hide window
user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.ShowWindow.restype = wintypes.BOOL

# UpdateWindow - Force window repaint
user32.UpdateWindow.argtypes = [wintypes.HWND]
user32.UpdateWindow.restype = wintypes.BOOL

# GetSysColorBrush - Get system color brush
user32.GetSysColorBrush.argtypes = [ctypes.c_int]
user32.GetSysColorBrush.restype = wintypes.HBRUSH

# Window procedure callback
def window_proc(hwnd, msg, wParam, lParam):
    """Simple window procedure that handles WM_DESTROY"""
    if msg == WM_DESTROY:
        user32.PostQuitMessage(0)
        return 0
    return user32.DefWindowProcW(hwnd, msg, wParam, lParam)


class OverlayTestWindow:
    """
    Creates a full-screen topmost overlay window for testing Layer 2 defense.
    Includes multiple failsafes to ensure the window is always cleaned up.
    """

    def __init__(self):
        self.hwnd = None
        self.class_name = "BlackholeOverlayTest"
        self.wnd_proc = WNDPROC(window_proc)
        self.cleanup_done = False
        self.timeout_seconds = 20
        self.start_time = None
        self.cleanup_lock = threading.Lock()
        self.hotkey_listener = None  # pynput keyboard listener

    def _get_screen_size(self):
        """Get primary screen dimensions"""
        width = user32.GetSystemMetrics(SM_CXSCREEN)
        height = user32.GetSystemMetrics(SM_CYSCREEN)
        return width, height

    def _register_window_class(self):
        """Register window class"""
        h_instance = kernel32.GetModuleHandleW(None)

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.style = 0
        wc.lpfnWndProc = self.wnd_proc
        wc.cbClsExtra = 0
        wc.cbWndExtra = 0
        wc.hInstance = h_instance
        wc.hIcon = None
        wc.hCursor = None
        wc.hbrBackground = user32.GetSysColorBrush(COLOR_WINDOW)
        wc.lpszMenuName = None
        wc.lpszClassName = self.class_name
        wc.hIconSm = None

        atom = user32.RegisterClassExW(ctypes.byref(wc))
        if atom == 0:
            error = kernel32.GetLastError()
            raise RuntimeError(f"Failed to register window class. Error: {error}")

        return atom

    def _create_window(self):
        """Create full-screen topmost overlay window"""
        h_instance = kernel32.GetModuleHandleW(None)
        width, height = self._get_screen_size()

        # Create window with WS_EX_TOPMOST (this is what Layer 2 detects)
        self.hwnd = user32.CreateWindowExW(
            WS_EX_TOPMOST,  # Extended style: topmost
            self.class_name,
            "Blackhole Layer 2 Test - Overlay Window",
            WS_POPUP | WS_VISIBLE,  # Borderless, visible
            0,  # x
            0,  # y
            width,  # width
            height,  # height
            None,  # hWndParent
            None,  # hMenu
            h_instance,
            None,  # lpParam
        )

        if not self.hwnd:
            error = kernel32.GetLastError()
            raise RuntimeError(f"Failed to create window. Error: {error}")

        # Ensure window is shown
        user32.ShowWindow(self.hwnd, SW_SHOW)
        user32.UpdateWindow(self.hwnd)

        # Double-check: Set topmost again to ensure it's on top
        user32.SetWindowPos(
            self.hwnd,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
        )

        print(f"[TEST] Overlay window created: HWND={self.hwnd}, Size={width}x{height}")

    def _stop_hotkey_listener(self):
        """Stop the global hotkey listener"""
        if self.hotkey_listener:
            try:
                self.hotkey_listener.stop()
                self.hotkey_listener = None
            except Exception as e:
                print(f"[TEST] WARNING: Failed to stop hotkey listener: {e}")

    def _cleanup_window(self):
        """Safely destroy the overlay window"""
        with self.cleanup_lock:
            if self.cleanup_done:
                return
            self.cleanup_done = True

        # Stop hotkey listener first
        self._stop_hotkey_listener()

        if self.hwnd and user32.IsWindow(self.hwnd):
            print("[TEST] Cleaning up overlay window...")

            # Try multiple cleanup methods
            try:
                # Method 1: Remove topmost style first (in case Blackhole didn't)
                user32.SetWindowPos(
                    self.hwnd,
                    HWND_NOTOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                )
            except Exception as e:
                print(f"[TEST] WARNING: Failed to remove topmost style: {e}")

            try:
                # Method 2: Hide window
                user32.ShowWindow(self.hwnd, SW_HIDE)
            except Exception as e:
                print(f"[TEST] WARNING: Failed to hide window: {e}")

            try:
                # Method 3: Destroy window
                if not user32.DestroyWindow(self.hwnd):
                    error = kernel32.GetLastError()
                    print(f"[TEST] WARNING: DestroyWindow failed. Error: {error}")
                else:
                    print("[TEST] Window destroyed successfully")
            except Exception as e:
                print(f"[TEST] WARNING: Exception during DestroyWindow: {e}")

            self.hwnd = None

        # Unregister window class
        try:
            h_instance = kernel32.GetModuleHandleW(None)
            user32.UnregisterClassW(self.class_name, h_instance)
        except Exception as e:
            print(f"[TEST] WARNING: Failed to unregister class: {e}")

    def _on_hotkey_press(self, key):
        """Handle global hotkey press (ESC key)"""
        try:
            # Check if ESC key was pressed
            if key == keyboard.Key.esc:
                if not self.cleanup_done:
                    print("\n[TEST] ESC key pressed! Emergency cleanup initiated...")
                    self._cleanup_window()
                    return False  # Stop listener after cleanup
        except Exception as e:
            print(f"[TEST] WARNING: Error in hotkey handler: {e}")
        return True  # Continue listening for other keys

    def _start_hotkey_listener(self):
        """Start global hotkey listener for ESC key"""
        if not PYNPUT_AVAILABLE:
            return

        try:
            # Create listener for ESC key
            self.hotkey_listener = keyboard.Listener(on_press=self._on_hotkey_press)
            self.hotkey_listener.start()
            print("[TEST] Global hotkey active: Press ESC to stop test (works even when screen is blanked)")
        except Exception as e:
            print(f"[TEST] WARNING: Failed to start hotkey listener: {e}")

    def _timeout_handler(self):
        """Timeout handler - automatically cleanup after timeout"""
        time.sleep(self.timeout_seconds)
        if not self.cleanup_done:
            print(f"\n[TEST] TIMEOUT: {self.timeout_seconds} seconds elapsed. Auto-cleaning up...")
            self._cleanup_window()

    def _countdown_display(self):
        """Display countdown timer (non-blocking)"""
        while not self.cleanup_done and self.start_time:
            elapsed = time.time() - self.start_time
            remaining = max(0, self.timeout_seconds - elapsed)

            if remaining > 0:
                print(f"\r[TEST] Overlay active. Time remaining: {remaining:.1f}s (Press Ctrl+C to stop)", end="", flush=True)
            else:
                print("\r[TEST] Timeout reached. Cleaning up...", end="", flush=True)
                break

            time.sleep(0.1)

    def run_test(self):
        """Run the overlay test with all safeguards"""
        print("=" * 70)
        print("Blackhole Layer 2 Defense Test - Overlay Window")
        print("=" * 70)
        print(f"[TEST] This will create a full-screen overlay for {self.timeout_seconds} seconds")
        print("[TEST] Blackhole's Layer 2 defense should detect and neutralize it")
        if PYNPUT_AVAILABLE:
            print("[TEST] Press ESC key at any time to stop (works even when screen is blanked)")
        print("[TEST] Press Ctrl+C at any time to stop the test early")
        print("=" * 70)
        print()

        timeout_thread = None
        countdown_thread = None

        try:
            # Start global hotkey listener (failsafe #1 - works even when screen is blanked)
            self._start_hotkey_listener()

            # Register window class
            self._register_window_class()

            # Create overlay window
            self._create_window()
            self.start_time = time.time()

            # Start timeout thread (failsafe #2)
            timeout_thread = threading.Thread(target=self._timeout_handler, daemon=True)
            timeout_thread.start()

            # Start countdown display (non-blocking)
            countdown_thread = threading.Thread(target=self._countdown_display, daemon=True)
            countdown_thread.start()

            print("[TEST] Overlay window is now active!")
            print("[TEST] If Blackhole is running, it should neutralize this window.")
            print("[TEST] Watch for the window to be moved behind other windows.")
            print()

            # Wait for timeout or manual stop
            while time.time() - self.start_time < self.timeout_seconds:
                if self.cleanup_done:
                    break
                time.sleep(0.1)

            print()  # New line after countdown

        except KeyboardInterrupt:
            # Failsafe #3: Keyboard interrupt
            print("\n[TEST] Keyboard interrupt (Ctrl+C) detected. Cleaning up...")

        except Exception as e:
            # Failsafe #4: Any unexpected error
            print(f"\n[TEST] ERROR: Unexpected exception: {type(e).__name__}: {e}")
            print("[TEST] Emergency cleanup initiated...")

        finally:
            # Failsafe #5: Always cleanup in finally block
            self._cleanup_window()

            # Wait for threads to finish
            if timeout_thread:
                timeout_thread.join(timeout=1)
            if countdown_thread:
                countdown_thread.join(timeout=1)

            print("[TEST] Test complete. Screen should be restored.")
            print("=" * 70)


def main():
    """Main entry point"""
    # Check if we're on Windows
    if sys.platform != "win32":
        print("ERROR: This test script is Windows-only.")
        sys.exit(1)

    # Run the test
    test = OverlayTestWindow()
    test.run_test()


if __name__ == "__main__":
    main()

