"""
Screen Blanking Defender
Implements two-layer defense against screen blanking attacks:
- Layer 1: Registry-based VDD driver blocking
- Layer 2: Event-driven overlay window neutralization
"""

import ctypes
import os
import subprocess
import threading
import time
import traceback
from ctypes import wintypes

from ..config import (
    DRIVER_BLOCK_ENABLED,
    DRIVER_BLOCK_HARDWARE_IDS,
    OVERLAY_NEUTRALIZATION_ENABLED,
    SCREEN_BLANKING_NOTIFICATION_ENABLED,
    SCREEN_BLANKING_NOTIFICATION_TITLE,
    SCREEN_BLANKING_NOTIFICATION_MESSAGE,
    SCREEN_BLANKING_NOTIFICATION_DURATION,
)
from ..system.win32_api import (
    user32,
    kernel32,
    ole32,
    WINEVENTPROC,
    WNDPROC,
    WNDCLASSEXW,
    EVENT_OBJECT_SHOW,
    EVENT_OBJECT_LOCATIONCHANGE,
    OBJID_WINDOW,
    CHILDID_SELF,
    WINEVENT_OUTOFCONTEXT,
    WINEVENT_SKIPOWNPROCESS,
    WS_EX_TOPMOST,
    GWL_EXSTYLE,
    WS_POPUP,
    WS_CAPTION,
    GWL_STYLE,
    MONITOR_DEFAULTTOPRIMARY,
    RECT,
    MONITORINFO,
    MSG,
    WM_QUIT,
    WM_APP,
    HWND_MESSAGE,
    SW_HIDE,
    PROCESS_QUERY_LIMITED_INFORMATION,
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
        
        # Message-only helper window for thread-safe neutralization
        self._helper_hwnd = None
        self._wnd_proc_ref = None  # Prevent GC of WNDPROC callback
        self._helper_class_name = "BlackholeHelperWindow"
        
        # Track windows for duration-based filtering
        self._tracked_windows = {}  # HWND -> first_detection_timestamp
        self._tracking_lock = threading.Lock()
                # Custom window messages
        self.WM_APP_NEUTRALIZE = WM_APP + 0x0001
        self.WM_APP_VERIFY = WM_APP + 0x0002
        self.WM_APP_PERSISTENCE_CHECK = WM_APP + 0x0003
        
        # Duration threshold (seconds) - windows must remain suspicious for this long
        self.PERSISTENCE_THRESHOLD = 1.0

        # Statistics
        self.stats = {
            "overlays_detected": 0,
            "overlays_neutralized": 0,
        }

    def _wnd_proc_callback(self, hwnd, msg, wParam, lParam):
        """
        Window procedure for the message-only helper window.
        Handles custom messages for neutralization and verification.
        """
        try:
            if msg == self.WM_APP_NEUTRALIZE:
                overlay_hwnd = lParam
                self._log(f"[SCREEN BLANK] WndProc: Received neutralization request for HWND {overlay_hwnd}")
                if self._neutralize_overlay(overlay_hwnd):
                    # Notify operator after successful neutralization
                    if SCREEN_BLANKING_NOTIFICATION_ENABLED:
                        self._notify_operator()
                return 0

            if msg == self.WM_APP_VERIFY:
                overlay_hwnd = lParam
                # Run verification in a separate thread to avoid blocking message loop
                threading.Thread(
                    target=self._verify_neutralization,
                    args=(overlay_hwnd,),
                    daemon=True,
                    name="NeutralizationVerifier"
                ).start()
                return 0

            if msg == self.WM_APP_PERSISTENCE_CHECK:
                overlay_hwnd = lParam
                threading.Thread(
                    target=self._verify_overlay_persistence,
                    args=(overlay_hwnd,),
                    daemon=True,
                    name="OverlayPersistenceCheck"
                ).start()
                return 0

            # Ensure wParam and lParam are valid integers (handle None case)
            safe_wParam = wParam if wParam is not None else 0
            safe_lParam = lParam if lParam is not None else 0
            return user32.DefWindowProcW(hwnd, msg, safe_wParam, safe_lParam)
        except Exception as e:
            self._log(f"[SCREEN BLANK] ERROR in _wnd_proc_callback: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")
            # Ensure wParam and lParam are valid integers (handle None case)
            safe_wParam = wParam if wParam is not None else 0
            safe_lParam = lParam if lParam is not None else 0
            try:
                return user32.DefWindowProcW(hwnd, msg, safe_wParam, safe_lParam)
            except Exception:
                # Last resort: return 0 if DefWindowProcW also fails
                return 0

    def _create_helper_window(self):
        """
        Create a message-only helper window for thread-safe neutralization.
        This window provides a message queue for PostMessage communication.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Initialize COM
            ole32.CoInitialize(0)
            
            # Get instance handle
            h_instance = kernel32.GetModuleHandleW(None)
            
            # Create WNDPROC callback and store reference to prevent GC
            self._wnd_proc_ref = WNDPROC(self._wnd_proc_callback)
            
            # Register window class
            wnd_class = WNDCLASSEXW()
            wnd_class.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wnd_class.style = 0
            wnd_class.lpfnWndProc = self._wnd_proc_ref
            wnd_class.cbClsExtra = 0
            wnd_class.cbWndExtra = 0
            wnd_class.hInstance = h_instance
            wnd_class.hIcon = None
            wnd_class.hCursor = None
            wnd_class.hbrBackground = None
            wnd_class.lpszMenuName = None
            wnd_class.lpszClassName = self._helper_class_name
            wnd_class.hIconSm = None
            
            atom = user32.RegisterClassExW(ctypes.byref(wnd_class))
            if atom == 0:
                error_code = kernel32.GetLastError()
                self._log(f"[SCREEN BLANK] ERROR: Failed to register helper window class. Error: {error_code}")
                ole32.CoUninitialize()
                return False
            
            # Create message-only window
            self._helper_hwnd = user32.CreateWindowExW(
                0,  # dwExStyle
                self._helper_class_name,
                "Blackhole Helper",
                0,  # dwStyle
                0,  # x
                0,  # y
                0,  # nWidth
                0,  # nHeight
                HWND_MESSAGE,  # hWndParent (message-only window)
                None,  # hMenu
                h_instance,
                None,  # lpParam
            )
            
            if not self._helper_hwnd:
                error_code = kernel32.GetLastError()
                self._log(f"[SCREEN BLANK] ERROR: Failed to create helper window. Error: {error_code}")
                UnregisterClassW(self._helper_class_name, h_instance)
                ole32.CoUninitialize()
                return False
            
            self._log(f"[SCREEN BLANK] Helper window created successfully (HWND: {self._helper_hwnd})")
            return True
            
        except Exception as e:
            self._log(f"[SCREEN BLANK] ERROR in _create_helper_window: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")
            if self._helper_hwnd:
                try:
                    DestroyWindow(self._helper_hwnd)
                except:
                    pass
                self._helper_hwnd = None
            try:
                UnregisterClassW(self._helper_class_name, kernel32.GetModuleHandleW(None))
            except:
                pass
            try:
                ole32.CoUninitialize()
            except:
                pass
            return False

    def _win_event_callback(
        self, hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime
    ):
        """
        WinEvent hook callback function.
        Called by Windows when EVENT_OBJECT_SHOW or EVENT_OBJECT_LOCATIONCHANGE occurs.
        This callback must be fast and non-blocking - it only posts messages.
        """
        try:
            # Filter for window-level events (both SHOW and LOCATIONCHANGE)
            if idObject != OBJID_WINDOW or idChild != CHILDID_SELF:
                return

            # Only process SHOW and LOCATIONCHANGE events
            if event != EVENT_OBJECT_SHOW and event != EVENT_OBJECT_LOCATIONCHANGE:
                return

            # Validate HWND
            if not user32.IsWindow(hwnd):
                return

            # DEBUG: Get window info for logging (throttled to avoid spam)
            event_name = "EVENT_OBJECT_SHOW" if event == EVENT_OBJECT_SHOW else "EVENT_OBJECT_LOCATIONCHANGE"
            title_buffer = ctypes.create_unicode_buffer(256)
            title_length = user32.GetWindowTextW(hwnd, title_buffer, 256)
            window_title = title_buffer.value if title_length > 0 else ""
            
            class_buffer = ctypes.create_unicode_buffer(256)
            class_length = user32.GetClassNameW(hwnd, class_buffer, 256)
            window_class = class_buffer.value if class_length > 0 else ""

            # Check if window is topmost
            ex_style = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
            if ex_style == 0:
                return  # GetWindowLongPtrW failed

            if not (ex_style & WS_EX_TOPMOST):
                return  # Not a topmost window

            # Check if window is full-screen
            if not self._is_fullscreen_topmost(hwnd):
                return

            # Additional filtering: Check if this is likely a screen blanking overlay
            # vs. a legitimate maximized window (e.g., PowerShell, browser, etc.)
            if not self._is_screen_blanking_overlay(hwnd):
                return  # Not a screen blanking overlay, skip

            # CRITICAL: Only neutralize visible windows - invisible windows can't blank the screen
            # If window is invisible, log it but don't neutralize
            if not user32.IsWindowVisible(hwnd):
                exe_path, exe_name = self._get_window_process_info(hwnd)
                if exe_path:
                    self._log(f"[SCREEN BLANK] Invisible full-screen window detected (HWND: {hwnd}, Process: {exe_name}, Path: {exe_path}, Title: '{window_title}', Class: '{window_class}') - not neutralizing")
                else:
                    self._log(f"[SCREEN BLANK] Invisible full-screen window detected (HWND: {hwnd}, Title: '{window_title}', Class: '{window_class}') - unable to get process info - not neutralizing")
                return  # Don't neutralize invisible windows

            # Check if we're already tracking this window
            with self._tracking_lock:
                if hwnd in self._tracked_windows:
                    return  # Already tracking, ignore duplicate detection
                
                # Record first detection time
                self._tracked_windows[hwnd] = time.time()

            # Schedule delayed persistence check instead of immediate neutralization
            if self._helper_hwnd:
                if not user32.PostMessageW(self._helper_hwnd, self.WM_APP_PERSISTENCE_CHECK, 0, hwnd):
                    error_code = kernel32.GetLastError()
                    self._log(f"[SCREEN BLANK] WARNING: Failed to schedule persistence check. Error: {error_code}")
                    with self._tracking_lock:
                        self._tracked_windows.pop(hwnd, None)
            else:
                with self._tracking_lock:
                    self._tracked_windows.pop(hwnd, None)
        except Exception as e:
            # Log full traceback for callback errors
            self._log(f"[SCREEN BLANK] ERROR in _win_event_callback: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")

    def _get_window_process_info(self, hwnd):
        """
        Get process information for a window handle.
        
        Args:
            hwnd: Window handle
            
        Returns:
            tuple: (exe_path, exe_name) or (None, None) if unable to get info
        """
        try:
            process_id = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
            
            if not process_id.value:
                self._log(f"[SCREEN BLANK] Unable to get process ID for window (HWND: {hwnd})")
                return (None, None)
            
            h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process_id.value)
            if not h_process:
                error_code = kernel32.GetLastError()
                self._log(f"[SCREEN BLANK] Unable to open process handle (HWND: {hwnd}, PID: {process_id.value}, Error: {error_code})")
                return (None, None)
            
            try:
                exe_path = ctypes.create_unicode_buffer(260)
                size = wintypes.DWORD(260)
                if kernel32.QueryFullProcessImageNameW(h_process, 0, exe_path, ctypes.byref(size)):
                    full_path = exe_path.value
                    exe_name = os.path.basename(full_path)
                    return (full_path, exe_name)
                error_code = kernel32.GetLastError()
                self._log(f"[SCREEN BLANK] Unable to query process image name (HWND: {hwnd}, PID: {process_id.value}, Error: {error_code})")
                return (None, None)
            finally:
                kernel32.CloseHandle(h_process)
        except Exception as e:
            self._log(f"[SCREEN BLANK] Exception getting process info (HWND: {hwnd}): {e}")
            return (None, None)

    def _is_microsoft_signed(self, exe_path):
        """
        Check if an executable is digitally signed by Microsoft Corporation.
        This is the FIRST and most reliable check to filter out legitimate Windows components.
        
        Args:
            exe_path: Full path to the executable
            
        Returns:
            bool: True if signed by Microsoft, False otherwise
        """
        if not exe_path:
            self._log(f"[SCREEN BLANK] Signature check: No exe_path provided")
            return False
        
        try:
            self._log(f"[SCREEN BLANK] Checking Microsoft signature for: {exe_path}")
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-AuthenticodeSignature '{exe_path}').SignerCertificate.Subject",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1.0,  # Increased timeout to 1 second
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            
            if result.returncode == 0:
                subject = result.stdout.strip()
                self._log(f"[SCREEN BLANK] Signature check result for {os.path.basename(exe_path)}: Subject='{subject}'")
                
                if "Microsoft Corporation" in subject or "Microsoft Windows" in subject:
                    self._log(f"[SCREEN BLANK] ✓ Microsoft-signed executable detected: {os.path.basename(exe_path)}")
                    return True
                else:
                    self._log(f"[SCREEN BLANK] ✗ Not Microsoft-signed: {os.path.basename(exe_path)} (Subject: '{subject}')")
            else:
                self._log(f"[SCREEN BLANK] PowerShell signature check failed for {os.path.basename(exe_path)}: returncode={result.returncode}, stderr='{result.stderr.strip()}'")
        except subprocess.TimeoutExpired:
            self._log(f"[SCREEN BLANK] Signature check TIMEOUT for {os.path.basename(exe_path)} (PowerShell took >1s)")
        except subprocess.SubprocessError as e:
            self._log(f"[SCREEN BLANK] Signature check subprocess error for {os.path.basename(exe_path)}: {e}")
        except Exception as e:
            self._log(f"[SCREEN BLANK] Signature check exception for {os.path.basename(exe_path)}: {e}")
        
        return False

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
            self._log(f"[SCREEN BLANK] Error checking full-screen: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")
            return False

    def _is_screen_blanking_overlay(self, hwnd):
        """
        Determine if a window is likely a screen blanking overlay.
        
        Screen blanking overlays have these characteristics:
        - Borderless (WS_POPUP, no WS_CAPTION)
        - Blank or generic window title
        - From RDP tool processes (optional check)
        - No visible UI elements
        
        Legitimate maximized windows (PowerShell, browsers, etc.) have:
        - Title bar (WS_CAPTION)
        - Window controls (minimize, maximize, close)
        - Meaningful window titles
        
        Args:
            hwnd: Window handle
            
        Returns:
            bool: True if likely a screen blanking overlay
        """
        try:
            # CHECK 0: Microsoft signature verification (FIRST CHECK - most reliable)
            # If the process is Microsoft-signed, it's a legitimate Windows component
            # This eliminates false positives from explorer.exe and other shell components
            process_id = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
            
            if not process_id.value:
                # Can't get process info, continue with other checks
                self._log(f"[SCREEN BLANK] Unable to get process ID for window (HWND: {hwnd}) - continuing with other checks")
                exe_path = None
                exe_name = None
            else:
                # Get process executable path
                exe_path, exe_name = self._get_window_process_info(hwnd)
                
                if not exe_path:
                    self._log(f"[SCREEN BLANK] Unable to get process executable path (HWND: {hwnd}, PID: {process_id.value}) - continuing with other checks")
                else:
                    # FIRST CHECK: Is this Microsoft-signed?
                    self._log(f"[SCREEN BLANK] Running Microsoft signature check for window (HWND: {hwnd}, Process: {exe_name})")
                    if self._is_microsoft_signed(exe_path):
                        self._log(f"[SCREEN BLANK] ✓ Window filtered out: Microsoft-signed process (HWND: {hwnd}, Process: {exe_name})")
                        return False  # Microsoft-signed = legitimate Windows component, not a screen blanking overlay
                    else:
                        self._log(f"[SCREEN BLANK] ✗ Not Microsoft-signed, continuing checks (HWND: {hwnd}, Process: {exe_name})")
            
            # Check 1: Window style - must be borderless (WS_POPUP without WS_CAPTION)
            style = user32.GetWindowLongPtrW(hwnd, GWL_STYLE)
            if style == 0:
                return False  # Failed to get style
            
            # Legitimate windows have WS_CAPTION (title bar)
            # Screen blanking overlays are WS_POPUP (borderless, no caption)
            has_caption = bool(style & WS_CAPTION)
            is_popup = bool(style & WS_POPUP)
            
            # If it has a caption bar, it's a legitimate window (PowerShell, browser, etc.)
            if has_caption:
                return False  # Not a screen blanking overlay
            
            # Must be popup style (borderless) to be considered
            if not is_popup:
                return False  # Not borderless, likely legitimate
            
            # Check 2: Window title - blank or very generic
            title_buffer = ctypes.create_unicode_buffer(256)
            title_length = user32.GetWindowTextW(hwnd, title_buffer, 256)
            window_title = title_buffer.value if title_length > 0 else ""
            
            # Check 3: Window class name
            class_buffer = ctypes.create_unicode_buffer(256)
            class_length = user32.GetClassNameW(hwnd, class_buffer, 256)
            window_class = class_buffer.value if class_length > 0 else ""
            
            # Check 4: Process name (optional - helps identify RDP tools)
            # Use process info we already got from the signature check above
            if exe_name:
                # Known RDP tools that might create overlays
                rdp_tools = ['anydesk.exe', 'teamviewer.exe', 'teamviewer_service.exe',
                            'ultraviewer.exe', 'ultraviewer_service.exe',
                            'rustdesk.exe', 'parsec.exe', 'logmein.exe',
                            'gotomeeting.exe', 'gotomypc.exe']
                if any(tool in exe_name for tool in rdp_tools):
                    # More likely to be a screen blanking overlay from RDP tool
                    return True
            
            # If we get here, it's a borderless popup window that is full-screen and topmost
            # This is HIGHLY suspicious - screen blanking overlays can have any title (or no title)
            # The title doesn't matter because the user can't see it anyway when the screen is blanked
            # A borderless + full-screen + topmost window is inherently a screen blanking overlay
            return True

        except Exception as e:
            self._log(f"[SCREEN BLANK] Error checking if screen blanking overlay: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")
            # On error, be conservative - don't neutralize
            return False

    def _neutralize_overlay(self, hwnd):
        """
        Neutralize overlay by hiding it using ShowWindow(SW_HIDE).

        Args:
            hwnd: Window handle to neutralize

        Returns:
            bool: True if successful
        """
        try:
            self._log(f"[SCREEN BLANK] Hiding overlay window (HWND: {hwnd})")

            # Call ShowWindow with SW_HIDE
            if not user32.ShowWindow(hwnd, SW_HIDE):
                error_code = kernel32.GetLastError()
                self._log(f"[SCREEN BLANK] WARNING: ShowWindow(SW_HIDE) failed. Error: {error_code}")
                return False

            self._log(f"[SCREEN BLANK] Overlay hidden successfully.")
            self.stats["overlays_neutralized"] += 1

            # Post a verification message to our own queue
            if self._helper_hwnd:
                user32.PostMessageW(self._helper_hwnd, self.WM_APP_VERIFY, 0, hwnd)

            return True

        except Exception as e:
            self._log(f"[SCREEN BLANK] Error neutralizing overlay: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")
            return False

    def _verify_overlay_persistence(self, hwnd):
        """
        Verify that an overlay window persists for the required duration before neutralizing.
        Filters out brief transitions and animations.
        """
        try:
            # Wait for the persistence threshold
            time.sleep(self.PERSISTENCE_THRESHOLD)
            
            # Check if window still exists
            if not user32.IsWindow(hwnd):
                with self._tracking_lock:
                    self._tracked_windows.pop(hwnd, None)
                return  # Window no longer exists
            
            # Re-verify all criteria silently
            if not user32.IsWindowVisible(hwnd):
                with self._tracking_lock:
                    self._tracked_windows.pop(hwnd, None)
                return
            
            ex_style = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
            if ex_style == 0 or not (ex_style & WS_EX_TOPMOST):
                with self._tracking_lock:
                    self._tracked_windows.pop(hwnd, None)
                return
            
            if not self._is_fullscreen_topmost(hwnd):
                with self._tracking_lock:
                    self._tracked_windows.pop(hwnd, None)
                return
            
            if not self._is_screen_blanking_overlay(hwnd):
                with self._tracking_lock:
                    self._tracked_windows.pop(hwnd, None)
                return
            
            # Window has persisted - this is a real threat
            with self._tracking_lock:
                first_detected = self._tracked_windows.pop(hwnd, None)
            
            # Get process info for logging
            exe_path, exe_name = self._get_window_process_info(hwnd)
            
            if first_detected:
                duration = time.time() - first_detected
                if exe_path:
                    self._log(f"[SCREEN BLANK] Overlay persisted for {duration:.2f}s - neutralizing (HWND: {hwnd}, Process: {exe_name}, Path: {exe_path})")
                else:
                    self._log(f"[SCREEN BLANK] Overlay persisted for {duration:.2f}s - neutralizing (HWND: {hwnd}) - unable to get process info")
            
            self.stats["overlays_detected"] += 1
            
            # Post neutralization message
            if self._helper_hwnd:
                if user32.PostMessageW(self._helper_hwnd, self.WM_APP_NEUTRALIZE, 0, hwnd):
                    self._log(f"[SCREEN BLANK] Neutralization request posted (HWND: {hwnd})")
                else:
                    error_code = kernel32.GetLastError()
                    self._log(f"[SCREEN BLANK] WARNING: Failed to post neutralization message. Error: {error_code}")
            
        except Exception as e:
            self._log(f"[SCREEN BLANK] ERROR in _verify_overlay_persistence: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")
            with self._tracking_lock:
                self._tracked_windows.pop(hwnd, None)

    def _verify_neutralization(self, hwnd):
        """
        Checks if a window's neutralization (hiding) was successful after a short delay.

        Args:
            hwnd: Window handle to verify
        """
        try:
            # Give the target process time to handle the async message
            time.sleep(0.1)

            # Check if window still exists
            if not user32.IsWindow(hwnd):
                self._log(f"[SCREEN BLANK] VERIFICATION SUCCEEDED: HWND {hwnd} no longer exists.")
                return

            # Check if window is visible
            if not user32.IsWindowVisible(hwnd):
                self._log(f"[SCREEN BLANK] VERIFICATION SUCCEEDED: HWND {hwnd} is hidden.")
            else:
                self._log(f"[SCREEN BLANK] VERIFICATION FAILED: HWND {hwnd} is still visible.")
                # Optional: Post another neutralization request
                # if self._helper_hwnd:
                #     user32.PostMessageW(self._helper_hwnd, self.WM_APP_NEUTRALIZE, 0, hwnd)

        except Exception as e:
            self._log(f"[SCREEN BLANK] Exception during verification of HWND {hwnd}: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")

    def _cleanup_helper_window(self):
        """
        Cleanup helper window, unregister class, and uninitialize COM.
        """
        try:
            h_instance = kernel32.GetModuleHandleW(None)
            
            if self._helper_hwnd:
                user32.DestroyWindow(self._helper_hwnd)
                self._helper_hwnd = None
                self._log("[SCREEN BLANK] Helper window destroyed")
            
            try:
                user32.UnregisterClassW(self._helper_class_name, h_instance)
                self._log("[SCREEN BLANK] Helper window class unregistered")
            except Exception as e:
                self._log(f"[SCREEN BLANK] WARNING: Failed to unregister class: {e}")
            
            try:
                ole32.CoUninitialize()
                self._log("[SCREEN BLANK] COM uninitialized")
            except Exception as e:
                self._log(f"[SCREEN BLANK] WARNING: Failed to uninitialize COM: {e}")
                
        except Exception as e:
            self._log(f"[SCREEN BLANK] ERROR in _cleanup_helper_window: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")

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
            # Log full traceback for notification errors (including win10toast WNDPROC issues)
            self._log(f"[NOTIFICATION] Error: {e}")
            self._log(f"[NOTIFICATION] Full traceback:\n{traceback.format_exc()}")

    def _hook_thread_func(self):
        """
        Thread function that installs hook and runs message loop.
        Must run in separate thread to process hook messages.
        """
        # Store this thread's ID for clean shutdown
        self._hook_thread_id = kernel32.GetCurrentThreadId()

        try:
            self._log("[SCREEN BLANK] Hook thread started")

            # Create callback reference (prevent garbage collection)
            self._hook_callback_ref = WINEVENTPROC(self._win_event_callback)

            # Create helper window first (required for PostMessage architecture)
            if not self._create_helper_window():
                self._log("[SCREEN BLANK] ERROR: Failed to create helper window. Cannot proceed.")
                return

            # Install hook
            self._hook = user32.SetWinEventHook(
                EVENT_OBJECT_SHOW,  # eventMin
                EVENT_OBJECT_LOCATIONCHANGE,  # eventMax (monitor both SHOW and LOCATIONCHANGE for re-promotion defense)
                None,  # hmodWinEventProc (NULL for out-of-context)
                self._hook_callback_ref,  # lpfnWinEventProc
                0,  # idProcess (all processes)
                0,  # idThread (all threads)
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            )

            if not self._hook:
                error_code = kernel32.GetLastError()
                self._log(
                    f"[SCREEN BLANK] ERROR: Failed to install hook. Error code: {error_code}"
                )
                # Cleanup helper window if hook failed
                self._cleanup_helper_window()
                return

            self._log("[SCREEN BLANK] Hook installed successfully")
            self._log(
                "[SCREEN BLANK] Overlay defender ACTIVE - monitoring for full-screen overlays"
            )

            # Efficient blocking message loop
            # GetMessageW blocks until a message arrives (0% CPU when idle)
            # Returns 0 when WM_QUIT is received, breaking the loop
            msg = MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            # Loop exits when WM_QUIT is received
            self._log("[SCREEN BLANK] Message loop exited")

        except Exception as e:
            self._log(f"[SCREEN BLANK] Error in hook thread: {e}")
            self._log(f"[SCREEN BLANK] Full traceback:\n{traceback.format_exc()}")

        finally:
            # Cleanup hook
            if self._hook:
                user32.UnhookWinEvent(self._hook)
                self._hook = None

            # Cleanup helper window and COM
            self._cleanup_helper_window()

            self._log("[SCREEN BLANK] Hook uninstalled")

    def start(self):
        """Start overlay monitoring"""
        if self._active:
            self._log("[SCREEN BLANK] Already active")
            return

        self._log("[SCREEN BLANK] Starting overlay defender...")
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

        self._log("[SCREEN BLANK] Stopping overlay defender...")
        self._active = False

        # Post WM_QUIT to hook thread - GetMessageW will return 0 and exit loop
        if self._hook_thread and self._hook_thread.is_alive() and self._hook_thread_id:
            user32.PostThreadMessageW(self._hook_thread_id, WM_QUIT, 0, 0)

        # Wait for thread to finish
        if self._hook_thread:
            self._hook_thread.join(timeout=2)

        self._log("[SCREEN BLANK] Overlay defender INACTIVE")

    def is_active(self):
        """Check if defender is currently active"""
        return self._active

    def get_stats(self):
        """Get statistics"""
        return self.stats.copy()

