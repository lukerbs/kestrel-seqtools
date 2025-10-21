# utils/win32_api.py
"""
Windows API definitions for Raw Input and Low-Level Hooks using ctypes.
Contains all necessary structures, constants, and function prototypes.
"""

import ctypes
from ctypes import wintypes

# ============================================================================
# CONSTANTS
# ============================================================================

# Window Messages
WM_INPUT = 0x00FF
WM_DESTROY = 0x0002
WM_QUIT = 0x0012

# Raw Input Device Info
RIDI_DEVICENAME = 0x20000007
RIDI_DEVICEINFO = 0x2000000B
RID_INPUT = 0x10000003

# Raw Input Device Flags
RIDEV_INPUTSINK = 0x00000100

# Raw Input Device Types
RIM_TYPEMOUSE = 0
RIM_TYPEKEYBOARD = 1
RIM_TYPEHID = 2

# Hook Types
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
HC_ACTION = 0

# Low-Level Hook Flags
LLKHF_INJECTED = 0x00000010
LLMHF_INJECTED = 0x00000001

# Keyboard Messages
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105

# Mouse Messages
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP = 0x0205
WM_MBUTTONDOWN = 0x0207
WM_MBUTTONUP = 0x0208
WM_MOUSEWHEEL = 0x020A
WM_MOUSEMOVE = 0x0200

# Window Creation
HWND_MESSAGE = wintypes.HWND(-3)
CS_HREDRAW = 0x0002
CS_VREDRAW = 0x0001
CW_USEDEFAULT = 0x80000000

# ============================================================================
# STRUCTURES
# ============================================================================


class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", POINT),
    ]


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        (
            "lpfnWndProc",
            ctypes.WINFUNCTYPE(wintypes.LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM),
        ),
        ("cbClsExtra", wintypes.INT),
        ("cbWndExtra", wintypes.INT),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HCURSOR),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


class RAWINPUTDEVICELIST(ctypes.Structure):
    _fields_ = [("hDevice", wintypes.HANDLE), ("dwType", wintypes.DWORD)]


class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", wintypes.DWORD),
        ("dwSize", wintypes.DWORD),
        ("hDevice", wintypes.HANDLE),
        ("wParam", wintypes.WPARAM),
    ]


class RAWMOUSE(ctypes.Structure):
    _fields_ = [
        ("usFlags", wintypes.USHORT),
        ("ulButtons", wintypes.ULONG),
        ("usButtonFlags", wintypes.USHORT),
        ("usButtonData", wintypes.USHORT),
        ("ulRawButtons", wintypes.ULONG),
        ("lLastX", wintypes.LONG),
        ("lLastY", wintypes.LONG),
        ("ulExtraInformation", wintypes.ULONG),
    ]


class RAWKEYBOARD(ctypes.Structure):
    _fields_ = [
        ("MakeCode", wintypes.USHORT),
        ("Flags", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("VKey", wintypes.USHORT),
        ("Message", wintypes.UINT),
        ("ExtraInformation", wintypes.ULONG),
    ]


class RAWHID(ctypes.Structure):
    _fields_ = [("dwSizeHid", wintypes.DWORD), ("dwCount", wintypes.DWORD), ("bRawData", wintypes.BYTE * 1)]


class RAWINPUT_DATA(ctypes.Union):
    _fields_ = [("mouse", RAWMOUSE), ("keyboard", RAWKEYBOARD), ("hid", RAWHID)]


class RAWINPUT(ctypes.Structure):
    _fields_ = [("header", RAWINPUTHEADER), ("data", RAWINPUT_DATA)]


class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [
        ("usUsagePage", wintypes.USHORT),
        ("usUsage", wintypes.USHORT),
        ("dwFlags", wintypes.DWORD),
        ("hwndTarget", wintypes.HWND),
    ]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG)),
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", POINT),
        ("mouseData", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG)),
    ]


# ============================================================================
# CALLBACK TYPES
# ============================================================================

WNDPROC = ctypes.WINFUNCTYPE(wintypes.LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
HOOKPROC = ctypes.CFUNCTYPE(wintypes.LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)

# ============================================================================
# LIBRARY HANDLES
# ============================================================================

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_last_error_string():
    """Get formatted Windows error message for the last error"""
    error_code = kernel32.GetLastError()
    error_msg = ctypes.create_unicode_buffer(256)
    kernel32.FormatMessageW(
        0x1100, None, error_code, 0, error_msg, 256, None  # FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
    )
    return f"Error Code {error_code}: {error_msg.value.strip()}"
