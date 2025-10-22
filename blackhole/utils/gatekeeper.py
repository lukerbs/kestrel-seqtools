# utils/gatekeeper.py
"""
Input Gatekeeper - Selective blocking using Raw Input API + Low-Level Hooks.
Uses ctypes to directly interact with Windows APIs for robust device identification.
"""

import queue
import threading
import ctypes
from ctypes import wintypes
import time

# Import Windows API definitions
from .win32_api import *
from .config import MAX_QUEUE_SIZE, HYPERVISOR_IDENTIFIERS

# ============================================================================
# GLOBAL STATE (Required for ctypes callbacks)
# ============================================================================

g_shared_queue = None
g_whitelist_set = None
g_keyboard_hook_handle = None
g_mouse_hook_handle = None
g_message_window_handle = None
g_raw_input_thread_id = None
g_hook_thread_id = None
g_log_func = lambda msg: None
g_stats = {"blocked_events": 0, "allowed_events": 0}

# CRITICAL: Keep references to prevent garbage collection
g_wndproc_ref = None
g_keyboard_hook_ref = None
g_mouse_hook_ref = None

# ============================================================================
# DEVICE WHITELIST BUILDER
# ============================================================================


def build_whitelist():
    """Enumerate Raw Input devices and identify hypervisor devices"""
    global g_log_func
    whitelist = set()

    g_log_func(f"[WHITELIST] Building whitelist with identifiers: {HYPERVISOR_IDENTIFIERS}")

    # Get device count
    device_count = wintypes.UINT(0)
    res = user32.GetRawInputDeviceList(None, ctypes.byref(device_count), ctypes.sizeof(RAWINPUTDEVICELIST))
    if res == -1 or device_count.value == 0:
        g_log_func("[ERROR] Failed to get raw input device count or no devices found")
        return whitelist

    # Get device list
    device_list_buffer = (RAWINPUTDEVICELIST * device_count.value)()
    res = user32.GetRawInputDeviceList(
        ctypes.cast(device_list_buffer, ctypes.POINTER(RAWINPUTDEVICELIST)),
        ctypes.byref(device_count),
        ctypes.sizeof(RAWINPUTDEVICELIST),
    )
    if res == -1:
        g_log_func(f"[ERROR] GetRawInputDeviceList failed: {get_last_error_string()}")
        return whitelist

    g_log_func(f"[WHITELIST] Found {device_count.value} raw input devices")

    # Check each device
    for device in device_list_buffer:
        if not device.hDevice:
            continue

        # Get device name
        name_buffer_size = wintypes.UINT(0)
        user32.GetRawInputDeviceInfoW(device.hDevice, RIDI_DEVICENAME, None, ctypes.byref(name_buffer_size))
        if name_buffer_size.value == 0:
            continue

        name_buffer = ctypes.create_unicode_buffer(name_buffer_size.value)
        user32.GetRawInputDeviceInfoW(device.hDevice, RIDI_DEVICENAME, name_buffer, ctypes.byref(name_buffer_size))
        device_name = name_buffer.value
        device_type = device.dwType

        # Whitelist keyboards and mice matching identifiers
        if device_type in [RIM_TYPEMOUSE, RIM_TYPEKEYBOARD]:
            if any(hid.upper() in device_name.upper() for hid in HYPERVISOR_IDENTIFIERS):
                whitelist.add(device.hDevice)
                type_str = "Keyboard" if device_type == RIM_TYPEKEYBOARD else "Mouse"
                g_log_func(f"[WHITELIST] ✓ Added {type_str}: {device_name} (Handle: {device.hDevice})")
            else:
                g_log_func(f"[WHITELIST] ✗ Ignored: {device_name} (Handle: {device.hDevice})")

    if not whitelist:
        g_log_func("[WARNING] No hypervisor input devices identified!")
    else:
        g_log_func(f"[WHITELIST] Built whitelist with {len(whitelist)} device(s)")

    return whitelist


# ============================================================================
# RAW INPUT THREAD
# ============================================================================


@WNDPROC
def RawInputWndProc(hwnd, msg, wParam, lParam):
    """Window procedure for Raw Input messages"""
    global g_shared_queue, g_whitelist_set, g_log_func

    if msg == WM_INPUT:
        # Get data size
        data_size = wintypes.UINT(0)
        user32.GetRawInputData(lParam, RID_INPUT, None, ctypes.byref(data_size), ctypes.sizeof(RAWINPUTHEADER))
        if data_size.value == 0:
            return user32.DefWindowProcW(hwnd, msg, wParam, lParam)

        # Get data
        data_buffer = ctypes.create_string_buffer(data_size.value)
        user32.GetRawInputData(lParam, RID_INPUT, data_buffer, ctypes.byref(data_size), ctypes.sizeof(RAWINPUTHEADER))
        raw_input = ctypes.cast(data_buffer, ctypes.POINTER(RAWINPUT)).contents
        device_handle = raw_input.header.hDevice
        device_type = raw_input.header.dwType

        # Make decision based on whitelist
        # CRITICAL: If device_handle is None/0, we can't identify it - default to ALLOW to prevent lockout
        if device_handle is None or device_handle == 0:
            decision = "ALLOW"
            reason = "Unknown device (default allow)"
        elif device_handle in g_whitelist_set:
            decision = "ALLOW"
            reason = "Device whitelisted"
        else:
            decision = "DENY"
            reason = "Device not whitelisted"

        # Detailed logging
        device_type_str = (
            "Keyboard" if device_type == RIM_TYPEKEYBOARD else "Mouse" if device_type == RIM_TYPEMOUSE else "HID"
        )
        in_whitelist = "YES" if device_handle in g_whitelist_set else "NO" if device_handle else "UNKNOWN"
        g_log_func(
            f"[RAW_INPUT] {device_type_str} event from handle {device_handle} | In whitelist: {in_whitelist} | Decision: {decision} ({reason})"
        )

        # Put decision on queue
        try:
            if g_shared_queue:
                g_shared_queue.put_nowait(decision)
        except queue.Full:
            g_log_func("[WARNING] Decision queue full!")
        except Exception as e:
            g_log_func(f"[ERROR] RawInputWndProc queue error: {e}")

        return user32.DefWindowProcW(hwnd, msg, wParam, lParam)

    elif msg == WM_DESTROY:
        user32.PostQuitMessage(0)
        return 0

    return user32.DefWindowProcW(hwnd, msg, wParam, lParam)


def _raw_input_thread_func():
    """Thread function to handle Raw Input messages"""
    global g_message_window_handle, g_raw_input_thread_id, g_log_func, g_wndproc_ref

    g_raw_input_thread_id = kernel32.GetCurrentThreadId()
    g_log_func("[RAW_INPUT] Thread started")

    hInstance = kernel32.GetModuleHandleW(None)
    class_name = "BlackholeRawInputWindow"

    # CRITICAL: Keep reference to prevent garbage collection
    g_wndproc_ref = RawInputWndProc

    # Register window class
    wnd_class = WNDCLASSEXW()
    wnd_class.cbSize = ctypes.sizeof(WNDCLASSEXW)
    wnd_class.lpfnWndProc = g_wndproc_ref
    wnd_class.hInstance = hInstance
    wnd_class.lpszClassName = class_name

    if not user32.RegisterClassExW(ctypes.byref(wnd_class)):
        g_log_func(f"[ERROR] Failed to register window class: {get_last_error_string()}")
        return

    # Create message-only window
    g_message_window_handle = user32.CreateWindowExW(
        0, class_name, "BlackholeRawInput", 0, 0, 0, 0, 0, HWND_MESSAGE, None, hInstance, None
    )

    if not g_message_window_handle:
        g_log_func(f"[ERROR] Failed to create message window: {get_last_error_string()}")
        user32.UnregisterClassW(class_name, hInstance)
        return

    g_log_func(f"[RAW_INPUT] Message window created (HWND: {g_message_window_handle})")

    # Register for Raw Input (keyboard and mouse)
    devices = (RAWINPUTDEVICE * 2)()

    # Keyboard
    devices[0].usUsagePage = 1
    devices[0].usUsage = 6
    devices[0].dwFlags = RIDEV_INPUTSINK
    devices[0].hwndTarget = g_message_window_handle

    # Mouse
    devices[1].usUsagePage = 1
    devices[1].usUsage = 2
    devices[1].dwFlags = RIDEV_INPUTSINK
    devices[1].hwndTarget = g_message_window_handle

    if not user32.RegisterRawInputDevices(devices, 2, ctypes.sizeof(RAWINPUTDEVICE)):
        g_log_func(f"[ERROR] Failed to register raw input devices: {get_last_error_string()}")
        user32.DestroyWindow(g_message_window_handle)
        user32.UnregisterClassW(class_name, hInstance)
        return

    g_log_func("[RAW_INPUT] Registered for raw input (keyboard + mouse)")

    # Message loop
    msg = MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))

    # Cleanup
    user32.UnregisterClassW(class_name, hInstance)
    g_message_window_handle = None
    g_log_func("[RAW_INPUT] Thread exiting")


# ============================================================================
# LOW-LEVEL HOOK THREAD
# ============================================================================


@HOOKPROC
def LowLevelKeyboardProc(nCode, wParam, lParam):
    """Callback for low-level keyboard hook"""
    global g_shared_queue, g_log_func, g_stats

    if nCode == HC_ACTION:
        try:
            decision = g_shared_queue.get_nowait() if g_shared_queue else "ALLOW"
            kb_struct = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents

            if decision == "DENY":
                g_stats["blocked_events"] += 1
                g_log_func(f"[HOOK BLOCKED] Keyboard vkCode={kb_struct.vkCode} | Reason: Device not whitelisted")
                return 1  # Block the event
            else:
                g_stats["allowed_events"] += 1
                g_log_func(f"[HOOK ALLOWED] Keyboard vkCode={kb_struct.vkCode} | Reason: Device whitelisted")
        except queue.Empty:
            # Queue empty - default to ALLOW to prevent lockout
            g_stats["allowed_events"] += 1
            kb_struct = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            g_log_func(f"[HOOK ALLOWED] Keyboard vkCode={kb_struct.vkCode} | Reason: Queue empty (default allow)")
        except Exception as e:
            g_log_func(f"[ERROR] Keyboard hook error: {e}")

    return user32.CallNextHookEx(None, nCode, wParam, lParam)


@HOOKPROC
def LowLevelMouseProc(nCode, wParam, lParam):
    """Callback for low-level mouse hook"""
    global g_shared_queue, g_log_func, g_stats

    if nCode == HC_ACTION:
        try:
            decision = g_shared_queue.get_nowait() if g_shared_queue else "ALLOW"
            ms_struct = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents

            if decision == "DENY":
                g_stats["blocked_events"] += 1
                g_log_func(
                    f"[HOOK BLOCKED] Mouse at ({ms_struct.pt.x}, {ms_struct.pt.y}) | Reason: Device not whitelisted"
                )
                return 1  # Block the event
            else:
                g_stats["allowed_events"] += 1
                g_log_func(
                    f"[HOOK ALLOWED] Mouse at ({ms_struct.pt.x}, {ms_struct.pt.y}) | Reason: Device whitelisted or unknown"
                )
        except queue.Empty:
            g_stats["allowed_events"] += 1
            ms_struct = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
            g_log_func(
                f"[HOOK ALLOWED] Mouse at ({ms_struct.pt.x}, {ms_struct.pt.y}) | Reason: Queue empty (default allow)"
            )
        except Exception as e:
            g_log_func(f"[ERROR] Mouse hook error: {e}")

    return user32.CallNextHookEx(None, nCode, wParam, lParam)


def _hook_thread_func():
    """Thread function to install hooks and run message loop"""
    global g_keyboard_hook_handle, g_mouse_hook_handle, g_hook_thread_id, g_log_func
    global g_keyboard_hook_ref, g_mouse_hook_ref

    g_hook_thread_id = kernel32.GetCurrentThreadId()
    g_log_func("[HOOKS] Thread started")

    hInstance = kernel32.GetModuleHandleW(None)

    # CRITICAL: Keep references to prevent garbage collection
    g_keyboard_hook_ref = LowLevelKeyboardProc
    g_mouse_hook_ref = LowLevelMouseProc

    # Install hooks
    g_keyboard_hook_handle = user32.SetWindowsHookExW(WH_KEYBOARD_LL, g_keyboard_hook_ref, hInstance, 0)
    g_mouse_hook_handle = user32.SetWindowsHookExW(WH_MOUSE_LL, g_mouse_hook_ref, hInstance, 0)

    if not g_keyboard_hook_handle or not g_mouse_hook_handle:
        g_log_func(f"[ERROR] Failed to install hooks: KBD={g_keyboard_hook_handle}, MOUSE={g_mouse_hook_handle}")
        g_log_func(f"[ERROR] {get_last_error_string()}")
        if g_keyboard_hook_handle:
            user32.UnhookWindowsHookEx(g_keyboard_hook_handle)
        if g_mouse_hook_handle:
            user32.UnhookWindowsHookEx(g_mouse_hook_handle)
        return

    g_log_func("[HOOKS] Keyboard and mouse hooks installed")

    # Message loop (required for hooks)
    msg = MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))

    # Cleanup
    if g_keyboard_hook_handle:
        user32.UnhookWindowsHookEx(g_keyboard_hook_handle)
    if g_mouse_hook_handle:
        user32.UnhookWindowsHookEx(g_mouse_hook_handle)
    g_keyboard_hook_handle = None
    g_mouse_hook_handle = None
    g_log_func("[HOOKS] Thread exiting")


# ============================================================================
# INPUT GATEKEEPER CLASS
# ============================================================================


class InputGatekeeper:
    """
    Selectively blocks non-whitelisted input using Raw Input API + Low-Level Hooks.
    """

    def __init__(self, log_func=None):
        global g_shared_queue, g_whitelist_set, g_log_func, g_stats

        g_log_func = log_func if log_func else lambda msg: None
        g_log_func("[GATEKEEPER] Initializing...")

        # Initialize global state
        g_shared_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        g_whitelist_set = build_whitelist()
        g_stats = {"blocked_events": 0, "allowed_events": 0}

        self._raw_input_thread = None
        self._hook_thread = None
        self._active = False

    def start(self):
        """Activate selective input blocking"""
        global g_log_func, g_shared_queue, g_whitelist_set

        if self._active:
            g_log_func("[WARNING] Gatekeeper already active")
            return

        g_log_func("[GATEKEEPER] Starting input firewall...")

        # Check if whitelist is empty (fail-safe #1)
        if not g_whitelist_set:
            g_log_func("[GATEKEEPER] CRITICAL: No whitelisted devices found!")
            g_log_func("[GATEKEEPER] FAIL-SAFE: Refusing to activate firewall to prevent lockout")
            g_log_func("[GATEKEEPER] Please check HYPERVISOR_IDENTIFIERS in config.py")
            g_log_func("[GATEKEEPER] Run debug_devices.ps1 to see available devices")
            return  # Abort activation

        # Fail-safe #2: Warn if Raw Input might not be working properly
        # If we can't identify devices, the firewall won't be able to distinguish host from remote input
        g_log_func("[GATEKEEPER] WARNING: If Raw Input returns 'None' for device handles,")
        g_log_func("[GATEKEEPER] the firewall will allow ALL input (cannot distinguish sources)")
        g_log_func("[GATEKEEPER] Monitor logs to ensure device identification is working")

        # Clear queue
        while not g_shared_queue.empty():
            try:
                g_shared_queue.get_nowait()
            except queue.Empty:
                break

        self._active = True

        # Start Raw Input thread
        self._raw_input_thread = threading.Thread(target=_raw_input_thread_func, daemon=True, name="RawInputThread")
        self._raw_input_thread.start()

        # Wait for window creation
        time.sleep(0.5)

        # Start Hook thread
        self._hook_thread = threading.Thread(target=_hook_thread_func, daemon=True, name="HookThread")
        self._hook_thread.start()

        g_log_func("[GATEKEEPER] Input firewall ACTIVE")

    def stop(self):
        """Deactivate and restore all input"""
        global g_message_window_handle, g_raw_input_thread_id, g_hook_thread_id, g_log_func
        global g_shared_queue, g_whitelist_set, g_keyboard_hook_handle, g_mouse_hook_handle

        if not self._active:
            g_log_func("[WARNING] Gatekeeper not active")
            return

        g_log_func("[GATEKEEPER] Stopping input firewall...")
        self._active = False

        # Signal threads to exit
        if g_message_window_handle and g_raw_input_thread_id:
            if not user32.PostThreadMessageW(g_raw_input_thread_id, WM_QUIT, 0, 0):
                g_log_func(f"[ERROR] Failed to post WM_QUIT to Raw Input thread: {get_last_error_string()}")

        if g_hook_thread_id and (g_keyboard_hook_handle or g_mouse_hook_handle):
            if not user32.PostThreadMessageW(g_hook_thread_id, WM_QUIT, 0, 0):
                g_log_func(f"[ERROR] Failed to post WM_QUIT to Hook thread: {get_last_error_string()}")

        # Wait for threads to finish
        if self._raw_input_thread:
            self._raw_input_thread.join(timeout=2)
            if self._raw_input_thread.is_alive():
                g_log_func("[WARNING] Raw Input thread did not exit gracefully")

        if self._hook_thread:
            self._hook_thread.join(timeout=2)
            if self._hook_thread.is_alive():
                g_log_func("[WARNING] Hook thread did not exit gracefully")

        # Reset global state
        g_shared_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        g_whitelist_set = None

        g_log_func("[GATEKEEPER] Input firewall INACTIVE")

    def is_active(self):
        """Check if firewall is currently active"""
        return self._active

    def get_stats(self):
        """Get statistics"""
        global g_stats
        return g_stats.copy()
