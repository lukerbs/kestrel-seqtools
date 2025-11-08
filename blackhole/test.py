import ctypes
from ctypes import wintypes
import threading
import time
import sys

# --- Constants ---
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
HC_ACTION = 0
WM_KEYDOWN = 0x0100
WM_QUIT = 0x0012

# Injected flags
LLKHF_INJECTED = 0x00000010
LLMHF_INJECTED = 0x00000001

# --- Type Definitions ---
LRESULT = ctypes.c_ssize_t
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)


# --- Structures ---
class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),  # ULONG_PTR
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", wintypes.POINT),
        ("mouseData", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),  # ULONG_PTR
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hWnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", wintypes.POINT),
    ]


# --- Win32 API Prototyping (THE FIX FOR ERROR 126) ---
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# SetWindowsHookExW
user32.SetWindowsHookExW.argtypes = [
    ctypes.c_int,  # idHook
    HOOKPROC,  # lpfn
    wintypes.HINSTANCE,  # hMod
    wintypes.DWORD,  # dwThreadId
]
user32.SetWindowsHookExW.restype = wintypes.HHOOK

# CallNextHookEx
user32.CallNextHookEx.argtypes = [
    wintypes.HHOOK,
    ctypes.c_int,
    wintypes.WPARAM,
    wintypes.LPARAM,
]
user32.CallNextHookEx.restype = LRESULT

# UnhookWindowsHookEx
user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
user32.UnhookWindowsHookEx.restype = wintypes.BOOL

# GetModuleHandleW
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE

# GetMessageW
user32.GetMessageW.argtypes = [
    ctypes.POINTER(MSG),
    wintypes.HWND,
    wintypes.UINT,
    wintypes.UINT,
]
user32.GetMessageW.restype = wintypes.BOOL

# TranslateMessage
user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
user32.TranslateMessage.restype = wintypes.BOOL

# DispatchMessageW
user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
user32.DispatchMessageW.restype = LRESULT

# PostThreadMessageW
user32.PostThreadMessageW.argtypes = [
    wintypes.DWORD,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
]
user32.PostThreadMessageW.restype = wintypes.BOOL

# GetCurrentThreadId
kernel32.GetCurrentThreadId.argtypes = []
kernel32.GetCurrentThreadId.restype = wintypes.DWORD

# GetLastError
kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD


def get_last_error_str():
    """Format GetLastError() as a string."""
    error_code = ctypes.get_last_error()
    if error_code == 0:
        return "No error"
    return f"Error {error_code}: {ctypes.FormatError(error_code)}"


class LowLevelHookManager:
    def __init__(self):
        self.kbd_hook = None
        self.mouse_hook = None
        self.hook_thread_id = None
        self.hook_thread = None

        # Store persistent references to prevent garbage collection
        self.kbd_proc_ref = HOOKPROC(self._keyboard_callback)
        self.mouse_proc_ref = HOOKPROC(self._mouse_callback)

    def _keyboard_callback(self, nCode, wParam, lParam):
        if nCode == HC_ACTION:
            try:
                kbd = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents

                # Check the LLKHF_INJECTED flag
                is_injected = (kbd.flags & LLKHF_INJECTED) != 0
                # Check dwExtraInfo
                extra_info = kbd.dwExtraInfo

                source = "[INJECTED]" if is_injected else "[HARDWARE]"

                if wParam == WM_KEYDOWN:
                    print(
                        f"KEYBOARD: {source} vkCode={kbd.vkCode:#04x} flags={kbd.flags:#010x} extraInfo={extra_info:#x}"
                    )
            except Exception as e:
                print(f"ERROR in keyboard_callback: {e}", file=sys.stderr)

        return user32.CallNextHookEx(self.kbd_hook, nCode, wParam, lParam)

    def _mouse_callback(self, nCode, wParam, lParam):
        if nCode == HC_ACTION:
            try:
                mouse = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents

                # Check the LLMHF_INJECTED flag
                is_injected = (mouse.flags & LLMHF_INJECTED) != 0
                # Check dwExtraInfo
                extra_info = mouse.dwExtraInfo

                source = "[INJECTED]" if is_injected else "[HARDWARE]"

                # Only print clicks to avoid spam
                if wParam in (0x0201, 0x0204, 0x0207):  # Button down events
                    print(f"MOUSE CLICK: {source} flags={mouse.flags:#010x} extraInfo={extra_info:#x}")
            except Exception as e:
                print(f"ERROR in mouse_callback: {e}", file=sys.stderr)

        return user32.CallNextHookEx(self.mouse_hook, nCode, wParam, lParam)

    def _hook_thread_target(self):
        """
        This function runs in the background thread.
        It sets the hooks and runs the message loop.
        """
        # Get the module handle for the current process (python.exe)
        # This is the correct value for hMod per the research report
        hInstance = kernel32.GetModuleHandleW(None)
        if not hInstance:
            print(f"Failed to get module handle: {get_last_error_str()}", file=sys.stderr)
            return

        # Store this thread's ID so we can post messages to it
        self.hook_thread_id = kernel32.GetCurrentThreadId()

        # Install Keyboard Hook
        self.kbd_hook = user32.SetWindowsHookExW(
            WH_KEYBOARD_LL, self.kbd_proc_ref, hInstance, 0  # dwThreadId = 0 for system-wide
        )
        if not self.kbd_hook:
            print(f"Failed to install keyboard hook: {get_last_error_str()}", file=sys.stderr)
            return

        # Install Mouse Hook
        self.mouse_hook = user32.SetWindowsHookExW(
            WH_MOUSE_LL, self.mouse_proc_ref, hInstance, 0  # dwThreadId = 0 for system-wide
        )
        if not self.mouse_hook:
            print(f"Failed to install mouse hook: {get_last_error_str()}", file=sys.stderr)
            # Clean up the kbd hook if mouse hook fails
            user32.UnhookWindowsHookEx(self.kbd_hook)
            return

        print("=" * 60)
        print("INPUT SOURCE DIAGNOSTIC TEST")
        print("=" * 60)
        print("Hooks installed successfully!")
        print("\n[HARDWARE] = Real local input (Mac via QEMU)")
        print("[INJECTED] = Synthetic input (SendInput/malware)")
        print("\nPress keys and click mouse to test...")
        print("Main thread will auto-exit in 30 seconds\n")

        # --- This is the required message loop ---
        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            if msg.message == WM_QUIT:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        # --- Cleanup ---
        print("\nHook message loop stopping...")
        user32.UnhookWindowsHookEx(self.kbd_hook)
        user32.UnhookWindowsHookEx(self.mouse_hook)
        self.kbd_hook = None
        self.mouse_hook = None
        print("Hooks uninstalled.")

    def start(self):
        if self.hook_thread is not None:
            print("Hook is already running.")
            return

        self.hook_thread = threading.Thread(target=self._hook_thread_target, daemon=True)
        self.hook_thread.start()
        # Give the thread time to install hooks
        time.sleep(0.5)

    def stop(self):
        if self.hook_thread is None or self.hook_thread_id is None:
            print("Hook is not running.")
            return

        # Post a WM_QUIT message to the hook thread to break its GetMessage loop
        user32.PostThreadMessageW(self.hook_thread_id, WM_QUIT, 0, 0)

        # Wait for the thread to finish
        self.hook_thread.join(timeout=2)
        self.hook_thread = None
        self.hook_thread_id = None
        print("Hook manager stopped.")


# --- Main execution with 30-second timeout ---
if __name__ == "__main__":
    print("Starting low-level input hook manager...")
    hook_manager = LowLevelHookManager()
    hook_manager.start()

    # 30-second auto-exit timer
    timeout = 30
    print(f"\n⚠️  EMERGENCY TIMEOUT: Script will auto-exit in {timeout} seconds")

    try:
        time.sleep(timeout)
        print(f"\n{timeout}-second timeout reached.")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received.")

    print("Stopping hook manager...")
    hook_manager.stop()
    print("Program exiting.")
