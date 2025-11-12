# utils/win32_api.py
"""
Windows API definitions for Raw Input and Low-Level Hooks using ctypes.
Contains all necessary structures, constants, and function prototypes.
"""

import ctypes
from ctypes import wintypes

# ============================================================================
# CUSTOM TYPE DEFINITIONS (not in wintypes)
# ============================================================================

# LRESULT is a signed pointer-sized integer (LONG_PTR)
# Must match platform pointer size: 64-bit on x64, 32-bit on x86
if ctypes.sizeof(ctypes.c_void_p) == 8:
    # 64-bit platform
    LRESULT = ctypes.c_int64
else:
    # 32-bit platform
    LRESULT = ctypes.c_long

# Handle types - these are all just opaque pointers (HANDLE wrappers)
# wintypes doesn't define these, so we define them as void pointers
HINSTANCE = ctypes.c_void_p
HICON = ctypes.c_void_p
HCURSOR = ctypes.c_void_p
HBRUSH = ctypes.c_void_p
HMONITOR = wintypes.HANDLE

# Platform-specific pointer-sized types
IS_64BIT = ctypes.sizeof(ctypes.c_void_p) == 8

if IS_64BIT:
    LONG_PTR = ctypes.c_int64
    ULONG_PTR = ctypes.c_uint64
else:
    LONG_PTR = ctypes.c_long
    ULONG_PTR = ctypes.c_ulong

# Windows parameter types (must match pointer size)
WPARAM = ULONG_PTR
LPARAM = LONG_PTR

# ============================================================================
# CONSTANTS
# ============================================================================

# Window Messages
WM_INPUT = 0x00FF
WM_DESTROY = 0x0002
WM_QUIT = 0x0012
WM_PAINT = 0x000F
WM_PEEK_MESSAGE = 0x0001  # PM_REMOVE flag for PeekMessageW
WM_APP = 0x8000

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
HWND_MESSAGE = wintypes.HWND(ctypes.c_void_p(-3).value)
CS_HREDRAW = 0x0002
CS_VREDRAW = 0x0001
CW_USEDEFAULT = 0x80000000

# ShowWindow Constants
SW_HIDE = 0

# WinEvent Hook Constants (for Layer 2 overlay detection)
EVENT_OBJECT_SHOW = 0x8002
EVENT_OBJECT_LOCATIONCHANGE = 0x800B
OBJID_WINDOW = 0x00000000
CHILDID_SELF = 0
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002

# Window Extended Styles
WS_EX_TOPMOST = 0x00000008
GWL_EXSTYLE = -20

# Window Styles (for filtering legitimate windows)
WS_POPUP = 0x80000000
WS_OVERLAPPED = 0x00000000
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_THICKFRAME = 0x00040000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX
GWL_STYLE = -16

# SetWindowPos Constants
HWND_NOTOPMOST = -2
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SWP_NOACTIVATE = 0x0010

# Monitor Constants
MONITOR_DEFAULTTOPRIMARY = 0x00000001

# ============================================================================
# STRUCTURES
# ============================================================================


class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", wintypes.LONG),
        ("top", wintypes.LONG),
        ("right", wintypes.LONG),
        ("bottom", wintypes.LONG),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", WPARAM),
        ("lParam", LPARAM),
        ("time", wintypes.DWORD),
        ("pt", POINT),
    ]


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        (
            "lpfnWndProc",
            ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM),
        ),
        ("cbClsExtra", wintypes.INT),
        ("cbWndExtra", wintypes.INT),
        ("hInstance", HINSTANCE),
        ("hIcon", HICON),
        ("hCursor", HCURSOR),
        ("hbrBackground", HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", HICON),
    ]


class RAWINPUTDEVICELIST(ctypes.Structure):
    _fields_ = [("hDevice", wintypes.HANDLE), ("dwType", wintypes.DWORD)]


class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", wintypes.DWORD),
        ("dwSize", wintypes.DWORD),
        ("hDevice", wintypes.HANDLE),
        ("wParam", WPARAM),
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
        ("dwExtraInfo", ULONG_PTR),  # Pointer-sized unsigned integer, not a pointer
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", POINT),
        ("mouseData", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),  # Pointer-sized unsigned integer, not a pointer
    ]


class MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", wintypes.DWORD),
    ]


class PAINTSTRUCT(ctypes.Structure):
    """PAINTSTRUCT for WM_PAINT handling"""
    _fields_ = [
        ("hdc", wintypes.HANDLE),  # HDC
        ("fErase", wintypes.BOOL),
        ("rcPaint", RECT),
        ("fRestore", wintypes.BOOL),
        ("fIncUpdate", wintypes.BOOL),
        ("rgbReserved", ctypes.c_char * 32),
    ]


HDC = wintypes.HANDLE


# ============================================================================
# CALLBACK TYPES
# ============================================================================

WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.INT, WPARAM, LPARAM)
WINEVENTPROC = ctypes.WINFUNCTYPE(
    None,  # VOID return
    wintypes.HANDLE,  # HWINEVENTHOOK hWinEventHook
    wintypes.DWORD,   # DWORD event
    wintypes.HWND,    # HWND hwnd
    wintypes.LONG,    # LONG idObject
    wintypes.LONG,    # LONG idChild
    wintypes.DWORD,   # DWORD dwEventThread
    wintypes.DWORD    # DWORD dwmsEventTime
)

# ============================================================================
# LIBRARY HANDLES
# ============================================================================

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# ============================================================================
# FUNCTION SIGNATURES
# ============================================================================
# Explicitly declare function signatures for type safety and correct conversions

# Window Management
user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
user32.DefWindowProcW.restype = LRESULT

user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
user32.RegisterClassExW.restype = wintypes.ATOM

user32.CreateWindowExW.argtypes = [
    wintypes.DWORD,  # dwExStyle
    wintypes.LPCWSTR,  # lpClassName
    wintypes.LPCWSTR,  # lpWindowName
    wintypes.DWORD,  # dwStyle
    wintypes.INT,  # x
    wintypes.INT,  # y
    wintypes.INT,  # nWidth
    wintypes.INT,  # nHeight
    wintypes.HWND,  # hWndParent
    wintypes.HMENU,  # hMenu
    HINSTANCE,  # hInstance
    wintypes.LPVOID,  # lpParam
]
user32.CreateWindowExW.restype = wintypes.HWND

user32.DestroyWindow.argtypes = [wintypes.HWND]
user32.DestroyWindow.restype = wintypes.BOOL

user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, HINSTANCE]
user32.UnregisterClassW.restype = wintypes.BOOL

# Message Loop
user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = wintypes.BOOL

user32.PeekMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT]
user32.PeekMessageW.restype = wintypes.BOOL

user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
user32.TranslateMessage.restype = wintypes.BOOL

user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
user32.DispatchMessageW.restype = LRESULT

user32.PostQuitMessage.argtypes = [wintypes.INT]
user32.PostQuitMessage.restype = None

user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, WPARAM, LPARAM]
user32.PostThreadMessageW.restype = wintypes.BOOL

# Raw Input
user32.GetRawInputDeviceList.argtypes = [
    ctypes.POINTER(RAWINPUTDEVICELIST),
    ctypes.POINTER(wintypes.UINT),
    wintypes.UINT,
]
user32.GetRawInputDeviceList.restype = wintypes.UINT

user32.GetRawInputDeviceInfoW.argtypes = [
    wintypes.HANDLE,
    wintypes.UINT,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.UINT),
]
user32.GetRawInputDeviceInfoW.restype = wintypes.UINT

user32.RegisterRawInputDevices.argtypes = [
    ctypes.POINTER(RAWINPUTDEVICE),
    wintypes.UINT,
    wintypes.UINT,
]
user32.RegisterRawInputDevices.restype = wintypes.BOOL

user32.GetRawInputData.argtypes = [
    LPARAM,  # hRawInput (passed as lParam)
    wintypes.UINT,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.UINT),
    wintypes.UINT,
]
user32.GetRawInputData.restype = wintypes.UINT

# Hooks
user32.SetWindowsHookExW.argtypes = [wintypes.INT, HOOKPROC, HINSTANCE, wintypes.DWORD]
user32.SetWindowsHookExW.restype = wintypes.HHOOK

user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
user32.UnhookWindowsHookEx.restype = wintypes.BOOL

user32.CallNextHookEx.argtypes = [wintypes.HHOOK, wintypes.INT, WPARAM, LPARAM]
user32.CallNextHookEx.restype = LRESULT

# WinEvent Hooks (for Layer 2 overlay detection)
user32.SetWinEventHook.argtypes = [
    wintypes.DWORD,      # eventMin
    wintypes.DWORD,      # eventMax
    wintypes.HMODULE,    # hmodWinEventProc
    WINEVENTPROC,        # lpfnWinEventProc
    wintypes.DWORD,      # idProcess
    wintypes.DWORD,      # idThread
    wintypes.DWORD       # dwFlags
]
user32.SetWinEventHook.restype = wintypes.HANDLE

user32.UnhookWinEvent.argtypes = [wintypes.HANDLE]
user32.UnhookWinEvent.restype = wintypes.BOOL

# Window Information Functions
user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowLongPtrW.restype = LONG_PTR

user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(RECT)]
user32.GetWindowRect.restype = wintypes.BOOL

user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
user32.MonitorFromWindow.restype = HMONITOR

user32.GetMonitorInfoW.argtypes = [HMONITOR, ctypes.POINTER(MONITORINFO)]
user32.GetMonitorInfoW.restype = wintypes.BOOL

user32.SetWindowPos.argtypes = [
    wintypes.HWND,      # hWnd
    wintypes.HWND,      # hWndInsertAfter
    ctypes.c_int,       # X
    ctypes.c_int,       # Y
    ctypes.c_int,       # cx
    ctypes.c_int,       # cy
    wintypes.UINT       # uFlags
]
user32.SetWindowPos.restype = wintypes.BOOL

user32.ShowWindow.argtypes = [wintypes.HWND, wintypes.INT]
user32.ShowWindow.restype = wintypes.BOOL

user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
user32.PostMessageW.restype = wintypes.BOOL

user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
user32.DefWindowProcW.restype = LRESULT

user32.DestroyWindow.argtypes = [wintypes.HWND]
user32.DestroyWindow.restype = wintypes.BOOL

user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, HINSTANCE]
user32.UnregisterClassW.restype = wintypes.BOOL

user32.IsWindow.argtypes = [wintypes.HWND]
user32.IsWindow.restype = wintypes.BOOL

user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL

user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int

user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int

user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD

user32.BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
user32.BeginPaint.restype = HDC

user32.EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
user32.EndPaint.restype = wintypes.BOOL

# Kernel Functions
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = HINSTANCE

kernel32.GetCurrentThreadId.argtypes = []
kernel32.GetCurrentThreadId.restype = wintypes.DWORD

kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

# Process Access Rights
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

kernel32.FormatMessageW.argtypes = [
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.LPVOID,
]
kernel32.FormatMessageW.restype = wintypes.DWORD

# COM Initialization
ole32 = ctypes.windll.ole32
ole32.CoInitialize.argtypes = [ctypes.c_void_p]
ole32.CoInitialize.restype = wintypes.LONG  # HRESULT is a 32-bit signed integer
ole32.CoUninitialize.argtypes = []
ole32.CoUninitialize.restype = None

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
