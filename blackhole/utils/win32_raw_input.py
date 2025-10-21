"""
Handles low-level Windows Raw Input API interactions using ctypes.
This module is responsible for:
1. Enumerating raw input devices to build a whitelist of hypervisor devices.
2. Running a background thread with a message-only window to listen for
   WM_INPUT messages, which contain the source device handle for each event.
3. Placing an ALLOW/DENY decision token onto a shared queue for each event.
"""

import ctypes
import queue
import threading
from ctypes import wintypes

# ============================================================================
# CTYPES DEFINITIONS FOR WIN32 API
# ============================================================================

# Basic types and handles
PUL = ctypes.POINTER(wintypes.ULONG)
HANDLE = wintypes.HANDLE
HWND = wintypes.HWND
HMODULE = wintypes.HMODULE
LPARAM = wintypes.LPARAM
WPARAM = wintypes.WPARAM
UINT = wintypes.UINT
DWORD = wintypes.DWORD
USHORT = wintypes.USHORT
LONG = wintypes.LONG
LRESULT = ctypes.c_ssize_t

# Constants
RIDI_DEVICENAME = 0x20000007
RID_INPUT = 0x10000003
RIDEV_INPUTSINK = 0x00000100
WM_INPUT = 0x00FF
WM_QUIT = 0x0012
HWND_MESSAGE = HWND(-3)


# Structures
class RAWINPUTDEVICELIST(ctypes.Structure):
    _fields_ = [
        ("hDevice", HANDLE),
        ("dwType", DWORD),
    ]


class RAWMOUSE(ctypes.Structure):
    _fields_ = [
        ("usFlags", USHORT),
        ("usButtonFlags", USHORT),
        ("usButtonData", USHORT),
        ("ulRawButtons", wintypes.ULONG),
        ("lLastX", LONG),
        ("lLastY", LONG),
        ("ulExtraInformation", wintypes.ULONG),
    ]


class RAWKEYBOARD(ctypes.Structure):
    _fields_ = [
        ("MakeCode", USHORT),
        ("Flags", USHORT),
        ("Reserved", USHORT),
        ("VKey", USHORT),
        ("Message", UINT),
        ("ExtraInformation", wintypes.ULONG),
    ]


class RAWHID(ctypes.Structure):
    _fields_ = [
        ("dwSizeHid", DWORD),
        ("dwCount", DWORD),
        ("bRawData", ctypes.c_byte * 1),
    ]


class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", DWORD),
        ("dwSize", DWORD),
        ("hDevice", HANDLE),
        ("wParam", WPARAM),
    ]


class RAWINPUT_DATA(ctypes.Union):
    _fields_ = [
        ("mouse", RAWMOUSE),
        ("keyboard", RAWKEYBOARD),
        ("hid", RAWHID),
    ]


class RAWINPUT(ctypes.Structure):
    _fields_ = [
        ("header", RAWINPUTHEADER),
        ("data", RAWINPUT_DATA),
    ]


class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [
        ("usUsagePage", USHORT),
        ("usUsage", USHORT),
        ("dwFlags", DWORD),
        ("hwndTarget", HWND),
    ]


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", UINT),
        ("style", UINT),
        ("lpfnWndProc", ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", HMODULE),
        ("hIcon", ctypes.c_void_p),
        ("hCursor", ctypes.c_void_p),
        ("hbrBackground", ctypes.c_void_p),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", ctypes.c_void_p),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", HWND),
        ("message", UINT),
        ("wParam", WPARAM),
        ("lParam", LPARAM),
        ("time", DWORD),
        ("pt", wintypes.POINT),
    ]


# Function prototypes
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# ============================================================================
# DEVICE ENUMERATION
# ============================================================================


def build_device_whitelist(identifiers, log_func):
    """
    Enumerates raw input devices and returns a set of handles for devices
    whose names match the given hypervisor identifiers.

    Args:
        identifiers: List of strings to match against device names (e.g., ["QEMU", "VMware"])
        log_func: Logging function

    Returns:
        set: Set of device handles that are whitelisted
    """
    device_count = UINT(0)
    user32.GetRawInputDeviceList(None, ctypes.byref(device_count), ctypes.sizeof(RAWINPUTDEVICELIST))

    if device_count.value == 0:
        log_func("[RAW_INPUT] No raw input devices found.")
        return set()

    device_list_buffer = (RAWINPUTDEVICELIST * device_count.value)()
    user32.GetRawInputDeviceList(
        ctypes.byref(device_list_buffer), ctypes.byref(device_count), ctypes.sizeof(RAWINPUTDEVICELIST)
    )

    whitelist = set()
    log_func(f"[RAW_INPUT] Found {device_count.value} raw input devices. Building whitelist...")

    for device in device_list_buffer:
        name_buffer_size = UINT(0)
        user32.GetRawInputDeviceInfoW(device.hDevice, RIDI_DEVICENAME, None, ctypes.byref(name_buffer_size))

        if name_buffer_size.value == 0:
            continue

        name_buffer = ctypes.create_unicode_buffer(name_buffer_size.value)
        user32.GetRawInputDeviceInfoW(device.hDevice, RIDI_DEVICENAME, name_buffer, ctypes.byref(name_buffer_size))
        device_name = name_buffer.value

        # Check if any identifier matches this device name
        if any(hid.lower() in device_name.lower() for hid in identifiers):
            whitelist.add(device.hDevice)
            device_type = "MOUSE" if device.dwType == 0 else "KEYBOARD" if device.dwType == 1 else "HID"
            log_func(f"[RAW_INPUT] ✓ Whitelisted: {device_name} (Type: {device_type}, Handle: {device.hDevice})")
        else:
            log_func(f"[RAW_INPUT]   Ignored: {device_name} (Handle: {device.hDevice})")

    if whitelist:
        log_func(f"[RAW_INPUT] Whitelist built: {len(whitelist)} devices")
    else:
        log_func("[RAW_INPUT] WARNING: No hypervisor devices found! All input may be blocked.")

    return whitelist


# ============================================================================
# RAW INPUT LISTENER THREAD
# ============================================================================


class RawInputThread(threading.Thread):
    """
    A dedicated thread to listen for WM_INPUT messages system-wide.
    Creates a message-only window and registers for raw input notifications.
    """

    def __init__(self, whitelist, decision_queue, log_func):
        """
        Initialize the Raw Input listener thread.

        Args:
            whitelist: Set of whitelisted device handles
            decision_queue: Queue to place ALLOW/DENY decisions
            log_func: Logging function
        """
        super().__init__(daemon=True, name="RawInputThread")
        self.whitelist = whitelist
        self.decision_queue = decision_queue
        self.log = log_func
        self.hwnd = None
        self.thread_id = None

    def run(self):
        """Main thread loop - creates window and processes messages"""
        self.thread_id = kernel32.GetCurrentThreadId()
        self.log("[RAW_INPUT] Starting listener thread...")

        # Define window procedure
        wnd_proc_ptr = ctypes.WINFUNCTYPE(LRESULT, HWND, UINT, WPARAM, LPARAM)(self._wnd_proc)

        # Register window class
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = wnd_proc_ptr
        wc.lpszClassName = "BlackholeRawInput"
        wc.hInstance = kernel32.GetModuleHandleW(None)

        if not user32.RegisterClassExW(ctypes.byref(wc)):
            self.log(f"[RAW_INPUT] ERROR: Failed to register window class. Code: {kernel32.GetLastError()}")
            return

        # Create message-only window
        self.hwnd = user32.CreateWindowExW(
            0, wc.lpszClassName, None, 0, 0, 0, 0, 0, HWND_MESSAGE, None, wc.hInstance, None
        )

        if not self.hwnd:
            self.log(f"[RAW_INPUT] ERROR: Failed to create message-only window. Code: {kernel32.GetLastError()}")
            return

        # Register for raw input (mouse and keyboard)
        devices = (RAWINPUTDEVICE * 2)()

        # Mouse (Usage Page 0x01, Usage 0x02)
        devices[0].usUsagePage = 0x01
        devices[0].usUsage = 0x02
        devices[0].dwFlags = RIDEV_INPUTSINK
        devices[0].hwndTarget = self.hwnd

        # Keyboard (Usage Page 0x01, Usage 0x06)
        devices[1].usUsagePage = 0x01
        devices[1].usUsage = 0x06
        devices[1].dwFlags = RIDEV_INPUTSINK
        devices[1].hwndTarget = self.hwnd

        if not user32.RegisterRawInputDevices(devices, 2, ctypes.sizeof(RAWINPUTDEVICE)):
            self.log(f"[RAW_INPUT] ERROR: Failed to register for raw input. Code: {kernel32.GetLastError()}")
            return

        self.log("[RAW_INPUT] Listener is active and monitoring input devices")

        # Message loop
        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        self.log("[RAW_INPUT] Listener thread stopped")

    def stop(self):
        """Stop the listener thread by posting WM_QUIT"""
        if self.thread_id:
            user32.PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0)

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        """
        Window procedure callback - handles WM_INPUT messages.
        Extracts device handle and places decision on queue.
        """
        if msg == WM_INPUT:
            # Get size of RAWINPUT structure
            size = UINT(0)
            user32.GetRawInputData(lparam, RID_INPUT, None, ctypes.byref(size), ctypes.sizeof(RAWINPUTHEADER))

            if size.value > 0:
                # Allocate buffer and get the data
                buf = (ctypes.c_byte * size.value)()
                user32.GetRawInputData(lparam, RID_INPUT, buf, ctypes.byref(size), ctypes.sizeof(RAWINPUTHEADER))

                # Cast to RAWINPUT structure
                raw = ctypes.cast(buf, ctypes.POINTER(RAWINPUT)).contents
                device_handle = raw.header.hDevice

                # Make decision based on whitelist
                decision = "ALLOW" if device_handle in self.whitelist else "DENY"

                # Place decision on queue (non-blocking)
                try:
                    self.decision_queue.put_nowait(decision)
                except queue.Full:
                    self.log("[RAW_INPUT] WARNING: Decision queue full, dropped decision")

        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
