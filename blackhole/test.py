import ctypes
from ctypes import wintypes
import threading
import time
import sys
import os
import traceback

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
HC_ACTION = 0

# Define LRESULT if not available (pointer-sized signed integer)
if hasattr(wintypes, "LRESULT"):
    LRESULT = wintypes.LRESULT
else:
    LRESULT = ctypes.c_ssize_t  # Pointer-sized signed int

# Define CallNextHookEx with proper types to handle large pointer values
user32.CallNextHookEx.argtypes = [
    wintypes.HHOOK,  # hhk
    ctypes.c_int,  # nCode
    wintypes.WPARAM,  # wParam
    wintypes.LPARAM,  # lParam
]
user32.CallNextHookEx.restype = LRESULT


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),  # Pointer-sized integer, not a pointer
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", wintypes.POINT),
        ("mouseData", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),  # Pointer-sized integer, not a pointer
    ]


HOOKPROC = ctypes.WINFUNCTYPE(
    LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM  # Return type  # nCode  # wParam  # lParam
)

# Global hook handles for emergency cleanup
g_kbd_hook = None
g_mouse_hook = None


def emergency_exit():
    """Emergency timeout - exits after 30 seconds in case input gets bricked"""
    time.sleep(30)
    print("\n" + "=" * 60)
    print("EMERGENCY TIMEOUT - Forcefully terminating after 30 seconds")
    print("=" * 60)

    # Try to unhook before exiting
    try:
        if g_kbd_hook:
            user32.UnhookWindowsHookEx(g_kbd_hook)
            print("Emergency: Keyboard hook removed")
        if g_mouse_hook:
            user32.UnhookWindowsHookEx(g_mouse_hook)
            print("Emergency: Mouse hook removed")
    except:
        pass

    # Force immediate exit of entire process (no cleanup, no exceptions)
    os._exit(0)


def keyboard_callback(nCode, wParam, lParam):
    try:
        if nCode == HC_ACTION:
            kbd = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            is_injected = kbd.flags & 0x00000010
            source = "[INJECTED]" if is_injected else "[HARDWARE]"
            print(f"KEYBOARD: {source} flags={kbd.flags:#010x} vkCode={kbd.vkCode}")
    except Exception as e:
        print(f"ERROR in keyboard_callback: {e}")

    # Must pass the specific hook handle, not None
    return user32.CallNextHookEx(g_kbd_hook, nCode, wParam, lParam)


def mouse_callback(nCode, wParam, lParam):
    try:
        if nCode == HC_ACTION:
            mouse = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
            is_injected = mouse.flags & 0x00000001
            source = "[INJECTED]" if is_injected else "[HARDWARE]"
            # Only print clicks to avoid spam
            if wParam in [0x0201, 0x0204, 0x0207]:  # Button down events
                print(f"MOUSE CLICK: {source} flags={mouse.flags:#010x}")
    except Exception as e:
        print(f"ERROR in mouse_callback: {e}")

    # Must pass the specific hook handle, not None
    return user32.CallNextHookEx(g_mouse_hook, nCode, wParam, lParam)


kbd_ref = HOOKPROC(keyboard_callback)
mouse_ref = HOOKPROC(mouse_callback)

# Get the module handle for the current process
hInstance = kernel32.GetModuleHandleW(None)
print(f"DEBUG: hInstance = {hInstance}")

# Install hooks with the module handle
print(f"DEBUG: Installing keyboard hook...")
print(f"DEBUG: WH_KEYBOARD_LL = {WH_KEYBOARD_LL}")
print(f"DEBUG: kbd_ref = {kbd_ref}")
print(f"DEBUG: hInstance = {hInstance}")

try:
    g_kbd_hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, kbd_ref, hInstance, 0)
    print(f"DEBUG: g_kbd_hook returned = {g_kbd_hook}")
    if not g_kbd_hook:
        error_code = kernel32.GetLastError()
        print(f"DEBUG: GetLastError = {error_code}")
        raise ctypes.WinError(error_code)

    print(f"DEBUG: Installing mouse hook...")
    g_mouse_hook = user32.SetWindowsHookExW(WH_MOUSE_LL, mouse_ref, hInstance, 0)
    print(f"DEBUG: g_mouse_hook returned = {g_mouse_hook}")
    if not g_mouse_hook:
        error_code = kernel32.GetLastError()
        print(f"DEBUG: GetLastError = {error_code}")
        user32.UnhookWindowsHookEx(g_kbd_hook)
        raise ctypes.WinError(error_code)
except Exception as e:
    print("\n" + "=" * 60)
    print("EXCEPTION OCCURRED:")
    print("=" * 60)
    traceback.print_exc()
    print("=" * 60)
    sys.exit(1)

print("=" * 60)
print("INPUT SOURCE DIAGNOSTIC TEST")
print("=" * 60)
print("\n[HARDWARE] = Real local input (Mac via QEMU)")
print("[INJECTED] = Synthetic input (SendInput/malware)")
print("\nPress keys and click mouse to test...")
print("To exit: Close this window or use Task Manager to kill python.exe")
print("\n⚠️  EMERGENCY TIMEOUT: Script will auto-exit in 30 seconds\n")

# Start emergency timeout thread
timeout_thread = threading.Thread(target=emergency_exit, daemon=True, name="EmergencyTimeout")
timeout_thread.start()

# Message loop
try:
    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))
except KeyboardInterrupt:
    print("\nExiting...")
finally:
    # Cleanup hooks
    if g_kbd_hook:
        user32.UnhookWindowsHookEx(g_kbd_hook)
    if g_mouse_hook:
        user32.UnhookWindowsHookEx(g_mouse_hook)
    print("Hooks removed.")
