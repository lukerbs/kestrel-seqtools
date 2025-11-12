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
import traceback
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
        WM_PAINT,
        PAINTSTRUCT,
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
COLOR_BACKGROUND = 1  # Black background for screen blanking
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

# GDI text drawing functions
gdi32 = ctypes.windll.gdi32

# CreateFontW - Create font
gdi32.CreateFontW.argtypes = [
    ctypes.c_int,  # nHeight
    ctypes.c_int,  # nWidth
    ctypes.c_int,  # nEscapement
    ctypes.c_int,  # nOrientation
    ctypes.c_int,  # fnWeight
    wintypes.DWORD,  # fdwItalic
    wintypes.DWORD,  # fdwUnderline
    wintypes.DWORD,  # fdwStrikeOut
    wintypes.DWORD,  # fdwCharSet
    wintypes.DWORD,  # fdwOutputPrecision
    wintypes.DWORD,  # fdwClipPrecision
    wintypes.DWORD,  # fdwQuality
    wintypes.DWORD,  # fdwPitchAndFamily
    wintypes.LPCWSTR,  # lpszFace
]
gdi32.CreateFontW.restype = wintypes.HANDLE  # HFONT

# SelectObject - Select font/brush into DC
gdi32.SelectObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]  # HDC, HGDIOBJ
gdi32.SelectObject.restype = wintypes.HANDLE

# SetTextColor
gdi32.SetTextColor.argtypes = [wintypes.HANDLE, wintypes.DWORD]  # HDC, COLORREF
gdi32.SetTextColor.restype = wintypes.DWORD

# SetBkColor
gdi32.SetBkColor.argtypes = [wintypes.HANDLE, wintypes.DWORD]  # HDC, COLORREF
gdi32.SetBkColor.restype = wintypes.DWORD

# SetBkMode
gdi32.SetBkMode.argtypes = [wintypes.HANDLE, ctypes.c_int]  # HDC, mode
gdi32.SetBkMode.restype = ctypes.c_int

# TextOutW - Draw text
user32.TextOutW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_int, wintypes.LPCWSTR, ctypes.c_int]
user32.TextOutW.restype = wintypes.BOOL

# DrawTextW - Draw formatted text
user32.DrawTextW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(RECT), wintypes.UINT]
user32.DrawTextW.restype = ctypes.c_int

# DeleteObject - Delete font
gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
gdi32.DeleteObject.restype = wintypes.BOOL

# GetClientRect - Get window client area
user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT)]
user32.GetClientRect.restype = wintypes.BOOL

# InvalidateRect - Invalidate window for repaint
user32.InvalidateRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT), wintypes.BOOL]
user32.InvalidateRect.restype = wintypes.BOOL

# Constants
FW_NORMAL = 400
FW_BOLD = 700
ANSI_CHARSET = 0
OUT_DEFAULT_PRECIS = 0
CLIP_DEFAULT_PRECIS = 0
DEFAULT_QUALITY = 0
DEFAULT_PITCH = 0
FF_DONTCARE = 0
TRANSPARENT = 1
DT_CENTER = 0x00000001
DT_VCENTER = 0x00000004
DT_SINGLELINE = 0x00000020
RGB_WHITE = 0x00FFFFFF
RGB_BLACK = 0x00000000

# Global dictionary to store countdown values per window
_overlay_countdowns = {}
_countdown_lock = threading.Lock()

# Window procedure callback
def window_proc(hwnd, msg, wParam, lParam):
    """Window procedure that handles WM_DESTROY and WM_PAINT"""
    try:
        if msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        elif msg == WM_PAINT:
            # Handle paint message and draw countdown
            ps = PAINTSTRUCT()
            hdc = user32.BeginPaint(hwnd, ctypes.byref(ps))
            if hdc:
                try:
                    # Get countdown value
                    with _countdown_lock:
                        countdown = _overlay_countdowns.get(hwnd, None)
                    
                    if countdown is not None:
                        # Get client rect for centering
                        client_rect = RECT()
                        user32.GetClientRect(hwnd, ctypes.byref(client_rect))
                        
                        # Create large font for countdown
                        font_height = -120  # Negative for character height
                        h_font = gdi32.CreateFontW(
                            font_height,  # nHeight
                            0,  # nWidth
                            0,  # nEscapement
                            0,  # nOrientation
                            FW_BOLD,  # fnWeight
                            0,  # fdwItalic
                            0,  # fdwUnderline
                            0,  # fdwStrikeOut
                            ANSI_CHARSET,  # fdwCharSet
                            OUT_DEFAULT_PRECIS,  # fdwOutputPrecision
                            CLIP_DEFAULT_PRECIS,  # fdwClipPrecision
                            DEFAULT_QUALITY,  # fdwQuality
                            DEFAULT_PITCH | FF_DONTCARE,  # fdwPitchAndFamily
                            "Arial"  # lpszFace
                        )
                        
                        if h_font:
                            # Select font into DC
                            old_font = gdi32.SelectObject(hdc, h_font)
                            
                            # Set text color to white
                            gdi32.SetTextColor(hdc, RGB_WHITE)
                            
                            # Set background mode to transparent
                            gdi32.SetBkMode(hdc, TRANSPARENT)
                            
                            # Format countdown text (as Unicode string)
                            countdown_text = f"{countdown:.1f}s"
                            
                            # Draw text centered
                            draw_rect = RECT()
                            draw_rect.left = client_rect.left
                            draw_rect.top = client_rect.top
                            draw_rect.right = client_rect.right
                            draw_rect.bottom = client_rect.bottom
                            
                            # DrawTextW expects LPCWSTR (pointer to null-terminated wide string)
                            text_buffer = ctypes.create_unicode_buffer(countdown_text)
                            user32.DrawTextW(
                                hdc,
                                text_buffer,
                                -1,  # -1 means null-terminated string
                                ctypes.byref(draw_rect),
                                DT_CENTER | DT_VCENTER | DT_SINGLELINE
                            )
                            
                            # Restore old font
                            gdi32.SelectObject(hdc, old_font)
                            gdi32.DeleteObject(h_font)
                except Exception as e:
                    # Log error but don't break painting
                    print(f"[TEST] ERROR drawing countdown: {e}")
                    print(traceback.format_exc())
                
                user32.EndPaint(hwnd, ctypes.byref(ps))
            return 0
        return user32.DefWindowProcW(hwnd, msg, wParam, lParam)
    except Exception as e:
        # Log full traceback for window procedure errors
        print(f"[TEST] ERROR in window_proc: {e}")
        print(traceback.format_exc())
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
        self.update_timer = None  # Timer for updating countdown display

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
        # Use black brush for screen blanking overlay (not white)
        wc.hbrBackground = user32.GetSysColorBrush(COLOR_BACKGROUND)
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
        
        # Register window in countdown dictionary
        with _countdown_lock:
            _overlay_countdowns[self.hwnd] = float(self.timeout_seconds)

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
        try:
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
                    print(traceback.format_exc())

                try:
                    # Method 2: Hide window
                    user32.ShowWindow(self.hwnd, SW_HIDE)
                except Exception as e:
                    print(f"[TEST] WARNING: Failed to hide window: {e}")
                    print(traceback.format_exc())

                try:
                    # Method 3: Destroy window
                    if not user32.DestroyWindow(self.hwnd):
                        error = kernel32.GetLastError()
                        print(f"[TEST] WARNING: DestroyWindow failed. Error: {error}")
                    else:
                        print("[TEST] Window destroyed successfully")
                except Exception as e:
                    print(f"[TEST] WARNING: Exception during DestroyWindow: {e}")
                    print(traceback.format_exc())

                self.hwnd = None

            # Unregister window class
            try:
                h_instance = kernel32.GetModuleHandleW(None)
                user32.UnregisterClassW(self.class_name, h_instance)
            except Exception as e:
                print(f"[TEST] WARNING: Failed to unregister class: {e}")
                print(traceback.format_exc())
            
            # Remove from countdown dictionary
            with _countdown_lock:
                _overlay_countdowns.pop(self.hwnd, None)
        except Exception as e:
            print(f"[TEST] CRITICAL ERROR in _cleanup_window: {e}")
            print(traceback.format_exc())

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
            # Log full traceback for hotkey errors (including pynput MSG structure issues)
            print(f"[TEST] ERROR in hotkey handler: {e}")
            print(traceback.format_exc())
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
            print(traceback.format_exc())

    def _timeout_handler(self):
        """Timeout handler - automatically cleanup after timeout"""
        try:
            time.sleep(self.timeout_seconds)
            if not self.cleanup_done:
                print(f"\n[TEST] TIMEOUT: {self.timeout_seconds} seconds elapsed. Auto-cleaning up...")
                self._cleanup_window()
        except Exception as e:
            print(f"[TEST] ERROR in timeout handler: {e}")
            print(traceback.format_exc())
            # Still try to cleanup on error
            if not self.cleanup_done:
                self._cleanup_window()

    def _countdown_display(self):
        """Display countdown timer and update overlay window"""
        while not self.cleanup_done and self.start_time:
            try:
                elapsed = time.time() - self.start_time
                remaining = max(0, self.timeout_seconds - elapsed)

                if remaining > 0:
                    # Update countdown in dictionary
                    with _countdown_lock:
                        if self.hwnd:
                            _overlay_countdowns[self.hwnd] = remaining
                    
                    # Invalidate window to trigger repaint
                    if self.hwnd and user32.IsWindow(self.hwnd):
                        try:
                            user32.InvalidateRect(self.hwnd, None, True)  # Invalidate entire window
                            user32.UpdateWindow(self.hwnd)  # Force immediate repaint
                        except Exception as e:
                            # If invalidation fails, continue anyway
                            pass
                    
                    print(f"\r[TEST] Overlay active. Time remaining: {remaining:.1f}s (Press Ctrl+C to stop)", end="", flush=True)
                else:
                    print("\r[TEST] Timeout reached. Cleaning up...", end="", flush=True)
                    break

                time.sleep(0.1)  # Update 10 times per second
            except Exception as e:
                print(f"[TEST] ERROR in countdown display: {e}")
                print(traceback.format_exc())
                time.sleep(0.1)  # Continue even on error

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
            print("[TEST] Full traceback:")
            print(traceback.format_exc())
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

