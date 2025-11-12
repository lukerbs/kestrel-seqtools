"""
Screen Blanking Defender
Implements two-layer defense against screen blanking attacks:
- Layer 1: Registry-based VDD driver blocking
- Layer 2: Event-driven overlay window neutralization
"""

import ctypes
import threading
import time
from ctypes import wintypes

from .config import (
    DRIVER_BLOCK_ENABLED,
    DRIVER_BLOCK_HARDWARE_IDS,
    OVERLAY_NEUTRALIZATION_ENABLED,
    SCREEN_BLANKING_NOTIFICATION_ENABLED,
    SCREEN_BLANKING_NOTIFICATION_TITLE,
    SCREEN_BLANKING_NOTIFICATION_MESSAGE,
    SCREEN_BLANKING_NOTIFICATION_DURATION,
)
from .win32_api import (
    user32,
    kernel32,
    WINEVENTPROC,
    EVENT_OBJECT_SHOW,
    OBJID_WINDOW,
    CHILDID_SELF,
    WINEVENT_OUTOFCONTEXT,
    WINEVENT_SKIPOWNPROCESS,
    WS_EX_TOPMOST,
    GWL_EXSTYLE,
    HWND_NOTOPMOST,
    SWP_NOMOVE,
    SWP_NOSIZE,
    SWP_NOACTIVATE,
    MONITOR_DEFAULTTOPRIMARY,
    RECT,
    MONITORINFO,
    MSG,
    WM_QUIT,
)


# ============================================================================
# LAYER 1: VDD DRIVER BLOCKING (Registry-based)
# ============================================================================


def apply_driver_block_registry(log_func=None):
    """
    Apply registry keys to block VDD driver installation.
    Idempotent: Safe to call multiple times.

    Registry Paths:
    - HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions
      - DenyDeviceIDs (REG_DWORD) = 1
      - DenyDeviceIDsRetroactive (REG_DWORD) = 1
    - HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs
      - 1, 2, 3, ... (REG_SZ) = Hardware ID strings

    Returns:
        bool: True if successful, False otherwise
    """
    log = log_func if log_func else lambda msg: None

    try:
        import winreg

        # Base registry path
        base_key_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        deny_ids_path = base_key_path + r"\DenyDeviceIDs"

        # Open or create base key
        try:
            base_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, base_key_path, 0, winreg.KEY_WRITE
            )
        except FileNotFoundError:
            base_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, base_key_path)

        # Set DenyDeviceIDs = 1 (idempotent)
        winreg.SetValueEx(base_key, "DenyDeviceIDs", 0, winreg.REG_DWORD, 1)
        log("[DRIVER_BLOCK] Set DenyDeviceIDs = 1")

        # Set DenyDeviceIDsRetroactive = 1 (CRITICAL - blocks pre-installed drivers)
        winreg.SetValueEx(
            base_key, "DenyDeviceIDsRetroactive", 0, winreg.REG_DWORD, 1
        )
        log("[DRIVER_BLOCK] Set DenyDeviceIDsRetroactive = 1")

        winreg.CloseKey(base_key)

        # Open or create DenyDeviceIDs subkey
        try:
            deny_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, deny_ids_path, 0, winreg.KEY_WRITE
            )
        except FileNotFoundError:
            deny_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, deny_ids_path)

        # Add Hardware IDs (idempotent - overwrites if exists)
        for idx, hw_id in enumerate(DRIVER_BLOCK_HARDWARE_IDS, start=1):
            winreg.SetValueEx(deny_key, str(idx), 0, winreg.REG_SZ, hw_id)
            log(f"[DRIVER_BLOCK] Added Hardware ID {idx}: {hw_id}")

        winreg.CloseKey(deny_key)

        log(
            f"[DRIVER_BLOCK] Registry keys applied successfully ({len(DRIVER_BLOCK_HARDWARE_IDS)} IDs)"
        )
        return True

    except PermissionError:
        log("[DRIVER_BLOCK] ERROR: Permission denied - requires administrator privileges")
        return False
    except Exception as e:
        log(f"[DRIVER_BLOCK] ERROR: Failed to apply registry: {type(e).__name__}: {e}")
        return False


def is_driver_block_active(log_func=None):
    """
    Check if driver block registry keys are active.

    Returns:
        bool: True if registry keys exist and are configured
    """
    log = log_func if log_func else lambda msg: None

    try:
        import winreg

        base_key_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

        try:
            base_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, base_key_path, 0, winreg.KEY_READ
            )

            # Check if DenyDeviceIDs is set to 1
            deny_device_ids, _ = winreg.QueryValueEx(base_key, "DenyDeviceIDs")
            winreg.CloseKey(base_key)

            return deny_device_ids == 1

        except FileNotFoundError:
            return False
        except Exception as e:
            log(f"[DRIVER_BLOCK] Error checking registry: {e}")
            return False

    except Exception as e:
        log(f"[DRIVER_BLOCK] Error: {e}")
        return False


# ============================================================================
# LAYER 2: OVERLAY NEUTRALIZATION (Event-driven hook)
# ============================================================================


class OverlayDefender:
    """
    Detects and neutralizes full-screen overlay windows using SetWinEventHook.
    Monitors for EVENT_OBJECT_SHOW and removes WS_EX_TOPMOST style from
    full-screen topmost windows.
    """

    def __init__(self, log_func=None):
        """
        Initialize the overlay defender.

        Args:
            log_func: Optional logging function
        """
        self._log = log_func if log_func else lambda msg: None
        self._hook = None
        self._hook_callback_ref = None
        self._active = False
        self._hook_thread = None
        self._hook_thread_id = None  # Store thread ID for clean shutdown

        # Statistics
        self.stats = {
            "overlays_detected": 0,
            "overlays_neutralized": 0,
        }

    def _win_event_callback(
        self, hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime
    ):
        """
        WinEvent hook callback function.
        Called by Windows when EVENT_OBJECT_SHOW occurs.
        """
        # Filter for the correct event type
        if event != EVENT_OBJECT_SHOW or idObject != OBJID_WINDOW or idChild != CHILDID_SELF:
            return

        # Validate HWND
        if not user32.IsWindow(hwnd):
            return

        # Check if window is topmost
        ex_style = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
        if ex_style == 0:
            return  # GetWindowLongPtrW failed

        if not (ex_style & WS_EX_TOPMOST):
            return  # Not a topmost window

        # Check if window is full-screen
        if not self._is_fullscreen_topmost(hwnd):
            return

        # Overlay detected - neutralize it
        self.stats["overlays_detected"] += 1
        self._log(f"[OVERLAY] Full-screen topmost overlay detected (HWND: {hwnd})")

        if self._neutralize_overlay(hwnd):
            self.stats["overlays_neutralized"] += 1
            self._log(f"[OVERLAY] Overlay neutralized successfully")

            # Notify operator
            if SCREEN_BLANKING_NOTIFICATION_ENABLED:
                self._notify_operator()
        else:
            self._log(f"[OVERLAY] WARNING: Failed to neutralize overlay")

    def _is_fullscreen_topmost(self, hwnd):
        """
        Check if a window is full-screen (covers entire monitor).

        Args:
            hwnd: Window handle

        Returns:
            bool: True if window is full-screen
        """
        try:
            # Get window rectangle
            wnd_rect = RECT()
            if not user32.GetWindowRect(hwnd, ctypes.byref(wnd_rect)):
                return False

            # Get monitor information
            h_monitor = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY)
            mon_info = MONITORINFO()
            mon_info.cbSize = ctypes.sizeof(MONITORINFO)

            if not user32.GetMonitorInfoW(h_monitor, ctypes.byref(mon_info)):
                return False

            # Compare window rect to monitor rect
            is_fullscreen = (
                wnd_rect.left == mon_info.rcMonitor.left
                and wnd_rect.top == mon_info.rcMonitor.top
                and wnd_rect.right == mon_info.rcMonitor.right
                and wnd_rect.bottom == mon_info.rcMonitor.bottom
            )

            return is_fullscreen

        except Exception as e:
            self._log(f"[OVERLAY] Error checking full-screen: {e}")
            return False

    def _neutralize_overlay(self, hwnd):
        """
        Neutralize overlay by removing WS_EX_TOPMOST style.

        Args:
            hwnd: Window handle to neutralize

        Returns:
            bool: True if successful
        """
        try:
            # Remove topmost style using SetWindowPos
            result = user32.SetWindowPos(
                hwnd,
                HWND_NOTOPMOST,  # Place behind other topmost windows
                0,
                0,
                0,
                0,  # No position/size change
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            )

            return bool(result)

        except Exception as e:
            self._log(f"[OVERLAY] Error neutralizing overlay: {e}")
            return False

    def _notify_operator(self):
        """
        Notify operator that screen blanking attempt was blocked.
        Uses win10toast for non-intrusive notification.
        """
        try:
            from win10toast import ToastNotifier

            toaster = ToastNotifier()
            toaster.show_toast(
                SCREEN_BLANKING_NOTIFICATION_TITLE,
                SCREEN_BLANKING_NOTIFICATION_MESSAGE,
                duration=SCREEN_BLANKING_NOTIFICATION_DURATION,
                threaded=True,  # Non-blocking
            )

            self._log(f"[NOTIFICATION] Toast notification sent")

        except ImportError:
            self._log(f"[NOTIFICATION] WARNING: win10toast not available")
        except Exception as e:
            # Silent failure - don't break service if notification fails
            self._log(f"[NOTIFICATION] Error: {e}")

    def _hook_thread_func(self):
        """
        Thread function that installs hook and runs message loop.
        Must run in separate thread to process hook messages.
        """
        # Store this thread's ID for clean shutdown
        self._hook_thread_id = kernel32.GetCurrentThreadId()

        try:
            self._log("[OVERLAY] Hook thread started")

            # Create callback reference (prevent garbage collection)
            self._hook_callback_ref = WINEVENTPROC(self._win_event_callback)

            # Install hook
            self._hook = user32.SetWinEventHook(
                EVENT_OBJECT_SHOW,  # eventMin
                EVENT_OBJECT_SHOW,  # eventMax
                None,  # hmodWinEventProc (NULL for out-of-context)
                self._hook_callback_ref,  # lpfnWinEventProc
                0,  # idProcess (all processes)
                0,  # idThread (all threads)
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            )

            if not self._hook:
                error_code = kernel32.GetLastError()
                self._log(
                    f"[OVERLAY] ERROR: Failed to install hook. Error code: {error_code}"
                )
                return

            self._log("[OVERLAY] Hook installed successfully")
            self._log(
                "[OVERLAY] Overlay defender ACTIVE - monitoring for full-screen overlays"
            )

            # Efficient blocking message loop
            # GetMessageW blocks until a message arrives (0% CPU when idle)
            # Returns 0 when WM_QUIT is received, breaking the loop
            msg = MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            # Loop exits when WM_QUIT is received
            self._log("[OVERLAY] Message loop exited")

        except Exception as e:
            self._log(f"[OVERLAY] Error in hook thread: {e}")

        finally:
            # Cleanup hook
            if self._hook:
                user32.UnhookWinEvent(self._hook)
                self._hook = None

            self._log("[OVERLAY] Hook uninstalled")

    def start(self):
        """Start overlay monitoring"""
        if self._active:
            self._log("[OVERLAY] Already active")
            return

        self._log("[OVERLAY] Starting overlay defender...")
        self._active = True

        # Start hook thread
        self._hook_thread = threading.Thread(
            target=self._hook_thread_func, daemon=True, name="OverlayDefenderHooks"
        )
        self._hook_thread.start()

        # Give hook time to install
        time.sleep(0.2)

    def stop(self):
        """Stop overlay monitoring"""
        if not self._active:
            return

        self._log("[OVERLAY] Stopping overlay defender...")
        self._active = False

        # Post WM_QUIT to hook thread - GetMessageW will return 0 and exit loop
        if self._hook_thread and self._hook_thread.is_alive() and self._hook_thread_id:
            user32.PostThreadMessageW(self._hook_thread_id, WM_QUIT, 0, 0)

        # Wait for thread to finish
        if self._hook_thread:
            self._hook_thread.join(timeout=2)

        self._log("[OVERLAY] Overlay defender INACTIVE")

    def is_active(self):
        """Check if defender is currently active"""
        return self._active

    def get_stats(self):
        """Get statistics"""
        return self.stats.copy()

