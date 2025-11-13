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
    from utils.system.win32_api import (
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
        MSG,
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

# TextOutW - Draw text (GDI function)
gdi32.TextOutW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_int, wintypes.LPCWSTR, ctypes.c_int]
gdi32.TextOutW.restype = wintypes.BOOL

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

# LoadCursorW - Load cursor resource
user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]  # hInstance, lpCursorName
user32.LoadCursorW.restype = wintypes.HANDLE  # HCURSOR

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
IDC_ARROW = 32512  # Standard arrow cursor

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
                    
                    # Log paint messages (throttled - only when countdown changes by whole second)
                    if countdown is not None:
                        current_second = int(countdown)
                        # Use a simple counter to throttle logging
                        if not hasattr(window_proc, '_last_paint_log'):
                            window_proc._last_paint_log = {}
                        if hwnd not in window_proc._last_paint_log or window_proc._last_paint_log[hwnd] != current_second:
                            print(f"[TEST] WM_PAINT received - drawing countdown: {countdown:.1f}s")
                            window_proc._last_paint_log[hwnd] = current_second
                    
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
        self.last_log_time = 0  # For throttling log messages
        self.paint_count = 0  # Count paint messages for logging

    def _get_screen_size(self):
        """Get primary screen dimensions"""
        width = user32.GetSystemMetrics(SM_CXSCREEN)
        height = user32.GetSystemMetrics(SM_CYSCREEN)
        return width, height

    def _register_window_class(self):
        """Register window class"""
        h_instance = kernel32.GetModuleHandleW(None)

        # Load standard arrow cursor to keep normal cursor appearance
        # For system cursors, we use MAKEINTRESOURCE (cast integer to LPCWSTR)
        h_cursor = user32.LoadCursorW(None, ctypes.cast(IDC_ARROW, wintypes.LPCWSTR))

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.style = 0
        wc.lpfnWndProc = self.wnd_proc
        wc.cbClsExtra = 0
        wc.cbWndExtra = 0
        wc.hInstance = h_instance
        wc.hIcon = None
        wc.hCursor = h_cursor  # Use arrow cursor instead of None
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
        print(f"[TEST] Window class: {self.class_name}, Style: WS_POPUP | WS_VISIBLE | WS_EX_TOPMOST")
        
        # Register window in countdown dictionary and trigger initial paint
        with _countdown_lock:
            _overlay_countdowns[self.hwnd] = float(self.timeout_seconds)
        
        # Trigger initial paint to display countdown immediately
        print("[TEST] Triggering initial window paint...")
        user32.InvalidateRect(self.hwnd, None, True)
        user32.UpdateWindow(self.hwnd)
        print("[TEST] Initial paint triggered - countdown should be visible")

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
                    print("[TEST] Cleanup already in progress - skipping")
                    return
                self.cleanup_done = True

            print("[TEST] ========== CLEANUP STARTED ==========")
            
            # Stop hotkey listener first
            print("[TEST] Stopping hotkey listener...")
            self._stop_hotkey_listener()
            print("[TEST] Hotkey listener stopped")

            if self.hwnd and user32.IsWindow(self.hwnd):
                print(f"[TEST] Cleaning up overlay window (HWND={self.hwnd})...")

                # Try multiple cleanup methods
                try:
                    # Method 1: Remove topmost style first (in case Blackhole didn't)
                    print("[TEST] Step 1: Removing WS_EX_TOPMOST style...")
                    user32.SetWindowPos(
                        self.hwnd,
                        HWND_NOTOPMOST,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                    )
                    print("[TEST] Step 1: Topmost style removed")
                except Exception as e:
                    print(f"[TEST] WARNING: Failed to remove topmost style: {e}")
                    print(traceback.format_exc())

                try:
                    # Method 2: Hide window
                    print("[TEST] Step 2: Hiding window...")
                    user32.ShowWindow(self.hwnd, SW_HIDE)
                    print("[TEST] Step 2: Window hidden")
                except Exception as e:
                    print(f"[TEST] WARNING: Failed to hide window: {e}")
                    print(traceback.format_exc())

                try:
                    # Method 3: Destroy window
                    print("[TEST] Step 3: Destroying window...")
                    if not user32.DestroyWindow(self.hwnd):
                        error = kernel32.GetLastError()
                        print(f"[TEST] WARNING: DestroyWindow failed. Error: {error}")
                    else:
                        print("[TEST] Step 3: Window destroyed successfully")
                except Exception as e:
                    print(f"[TEST] WARNING: Exception during DestroyWindow: {e}")
                    print(traceback.format_exc())

                self.hwnd = None
            else:
                print("[TEST] Window handle is invalid or already destroyed")

            # Unregister window class
            try:
                print("[TEST] Step 4: Unregistering window class...")
                h_instance = kernel32.GetModuleHandleW(None)
                user32.UnregisterClassW(self.class_name, h_instance)
                print("[TEST] Step 4: Window class unregistered")
            except Exception as e:
                print(f"[TEST] WARNING: Failed to unregister class: {e}")
                print(traceback.format_exc())
            
            # Remove from countdown dictionary
            with _countdown_lock:
                _overlay_countdowns.pop(self.hwnd, None)
            
            print("[TEST] ========== CLEANUP COMPLETE ==========")
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
            # Note: pynput may show a thread exception on some Windows versions
            # This is a known compatibility issue and doesn't affect the overlay test
            self.hotkey_listener = keyboard.Listener(on_press=self._on_hotkey_press)
            self.hotkey_listener.start()
            print("[TEST] Global hotkey active: Press ESC to stop test (works even when screen is blanked)")
            print("[TEST] NOTE: If you see a pynput thread error, it's harmless - overlay still works")
        except Exception as e:
            print(f"[TEST] WARNING: Failed to start hotkey listener: {e}")
            print("[TEST] NOTE: Hotkey (ESC) may not work, but Ctrl+C and timeout still work")
            print(traceback.format_exc())

    def _timeout_handler(self):
        """Timeout handler - automatically cleanup after timeout"""
        print(f"[TEST] Timeout handler thread started - will trigger cleanup after {self.timeout_seconds}s")
        try:
            time.sleep(self.timeout_seconds)
            if not self.cleanup_done:
                print(f"\n[TEST] ========== TIMEOUT TRIGGERED ==========")
                print(f"[TEST] {self.timeout_seconds} seconds elapsed. Auto-cleaning up...")
                self._cleanup_window()
            else:
                print("[TEST] Timeout handler: Cleanup already in progress, skipping")
        except Exception as e:
            print(f"[TEST] ERROR in timeout handler: {e}")
            print(traceback.format_exc())
            # Still try to cleanup on error
            if not self.cleanup_done:
                print("[TEST] Timeout handler: Attempting emergency cleanup due to error")
                self._cleanup_window()

    def _countdown_display(self):
        """Display countdown timer and update overlay window"""
        print("[TEST] Countdown display thread started")
        last_logged_second = -1
        
        while not self.cleanup_done and self.start_time:
            try:
                elapsed = time.time() - self.start_time
                remaining = max(0, self.timeout_seconds - elapsed)
                current_second = int(remaining)

                if remaining > 0:
                    # Update countdown in dictionary
                    with _countdown_lock:
                        if self.hwnd:
                            _overlay_countdowns[self.hwnd] = remaining
                    
                    # Log every second (not every 0.1s to avoid spam)
                    if current_second != last_logged_second:
                        print(f"[TEST] Countdown: {remaining:.1f}s remaining - updating overlay display")
                        last_logged_second = current_second
                    
                    # Invalidate window to trigger repaint
                    if self.hwnd and user32.IsWindow(self.hwnd):
                        try:
                            user32.InvalidateRect(self.hwnd, None, True)  # Invalidate entire window
                            user32.UpdateWindow(self.hwnd)  # Force immediate repaint
                        except Exception as e:
                            # If invalidation fails, log it
                            if current_second != last_logged_second:  # Only log once per second
                                print(f"[TEST] WARNING: Failed to invalidate window: {e}")
                else:
                    print("\n[TEST] Countdown reached zero - timeout triggered")
                    break

                time.sleep(0.1)  # Update 10 times per second
            except Exception as e:
                print(f"[TEST] ERROR in countdown display: {e}")
                print(traceback.format_exc())
                time.sleep(0.1)  # Continue even on error
        
        print("[TEST] Countdown display thread exiting")

    def _message_loop(self):
        """Window message loop - processes WM_PAINT and other messages"""
        try:
            msg = MSG()
            # Process messages until window is destroyed or cleanup is done
            # Use PeekMessage for non-blocking message processing
            while not self.cleanup_done and self.hwnd and user32.IsWindow(self.hwnd):
                # PeekMessage with PM_REMOVE to get and remove messages
                # Filter by our window handle to only get messages for our window
                result = user32.PeekMessageW(ctypes.byref(msg), self.hwnd, 0, 0, 0x0001)  # PM_REMOVE
                if result:
                    # Process the message
                    if msg.message == WM_QUIT:
                        break
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                else:
                    # Also check for messages in the thread queue (NULL HWND)
                    # This helps catch messages that might be queued differently
                    result = user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 0x0001)  # PM_REMOVE
                    if result:
                        # Only process if it's for our window
                        if msg.hwnd == self.hwnd:
                            if msg.message == WM_QUIT:
                                break
                            user32.TranslateMessage(ctypes.byref(msg))
                            user32.DispatchMessageW(ctypes.byref(msg))
                    else:
                        # No messages, sleep briefly to avoid busy-wait
                        time.sleep(0.01)  # 10ms sleep
        except Exception as e:
            print(f"[TEST] ERROR in message loop: {e}")
            print(traceback.format_exc())

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

            # Main loop: process window messages and wait for timeout
            print("[TEST] Starting main message loop...")
            msg = MSG()
            message_count = 0
            last_message_log_time = time.time()
            
            while time.time() - self.start_time < self.timeout_seconds:
                if self.cleanup_done:
                    print("[TEST] Cleanup flag set - exiting main loop")
                    break
                
                # Process window messages (non-blocking)
                # This is required for WM_PAINT to be processed
                messages_processed = 0
                while user32.PeekMessageW(ctypes.byref(msg), self.hwnd, 0, 0, 0x0001):  # PM_REMOVE
                    if msg.message == WM_QUIT:
                        print("[TEST] WM_QUIT received - exiting message loop")
                        break
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                    messages_processed += 1
                    message_count += 1
                
                # Log message processing stats every 5 seconds (throttled)
                current_time = time.time()
                if current_time - last_message_log_time >= 5.0:
                    if messages_processed > 0:
                        print(f"[TEST] Message loop active - processed {message_count} messages total")
                    last_message_log_time = current_time
                
                time.sleep(0.05)  # 50ms sleep to avoid busy-wait

            print()  # New line after countdown

        except KeyboardInterrupt:
            # Failsafe #3: Keyboard interrupt
            print("\n[TEST] ========== KEYBOARD INTERRUPT ==========")
            print("[TEST] Ctrl+C detected. Initiating cleanup...")

        except Exception as e:
            # Failsafe #4: Any unexpected error
            print(f"\n[TEST] ========== UNEXPECTED ERROR ==========")
            print(f"[TEST] Exception type: {type(e).__name__}")
            print(f"[TEST] Exception message: {e}")
            print("[TEST] Full traceback:")
            print(traceback.format_exc())
            print("[TEST] Emergency cleanup initiated...")

        finally:
            # Failsafe #5: Always cleanup in finally block
            print("\n[TEST] ========== FINALLY BLOCK ==========")
            print("[TEST] Ensuring cleanup is performed...")
            self._cleanup_window()

            # Wait for threads to finish
            print("[TEST] Waiting for threads to finish...")
            if timeout_thread:
                timeout_thread.join(timeout=1)
                print("[TEST] Timeout thread joined")
            if countdown_thread:
                countdown_thread.join(timeout=1)
                print("[TEST] Countdown thread joined")

            print("\n[TEST] ========== TEST COMPLETE ==========")
            print("[TEST] Screen should be restored.")
            print("=" * 70)


def main():
    """Main entry point"""
    # Check if we're on Windows
    if sys.platform != "win32":
        print("ERROR: This test script is Windows-only.")
        sys.exit(1)

    # Suppress pynput thread exceptions (known compatibility issue)
    # Python 3.8+ has threading.excepthook
    if hasattr(threading, 'excepthook'):
        original_excepthook = threading.excepthook
        
        def thread_exception_handler(args):
            """Handle uncaught exceptions in threads - suppress pynput errors"""
            # Check if this is a pynput MSG structure compatibility error
            error_str = str(args.exc_value) if hasattr(args, 'exc_value') else str(args)
            if 'MSG' in error_str or 'ArgumentError' in str(args.exc_type):
                # Silently ignore pynput compatibility errors
                return
            # For other exceptions, use original handler
            if original_excepthook:
                original_excepthook(args)
            else:
                print(f"[TEST] Unhandled exception in thread: {args.exc_type.__name__}: {args.exc_value}")
        
        threading.excepthook = thread_exception_handler

    # Run the test
    test = OverlayTestWindow()
    test.run_test()


if __name__ == "__main__":
    main()

