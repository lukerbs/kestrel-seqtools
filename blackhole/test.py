import ctypes
from ctypes import wintypes
import threading
import time
import sys

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
HC_ACTION = 0


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
        ("pt", wintypes.POINT),
        ("mouseData", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG)),
    ]


HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)


def emergency_exit():
    """Emergency timeout - exits after 60 seconds in case input gets bricked"""
    time.sleep(60)
    print("\n" + "=" * 60)
    print("EMERGENCY TIMEOUT - Exiting after 60 seconds")
    print("=" * 60)
    # Force exit
    sys.exit(0)


def keyboard_callback(nCode, wParam, lParam):
    try:
        if nCode == HC_ACTION:
            kbd = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            is_injected = kbd.flags & 0x00000010
            source = "[INJECTED]" if is_injected else "[HARDWARE]"
            print(f"KEYBOARD: {source} flags={kbd.flags:#010x} vkCode={kbd.vkCode}")
    except Exception as e:
        print(f"ERROR in keyboard_callback: {e}")

    return user32.CallNextHookEx(None, nCode, wParam, lParam)


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

    return user32.CallNextHookEx(None, nCode, wParam, lParam)


kbd_ref = HOOKPROC(keyboard_callback)
mouse_ref = HOOKPROC(mouse_callback)

# For low-level hooks (LL), hInstance must be NULL
kbd_hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, kbd_ref, None, 0)
if not kbd_hook:
    error_code = kernel32.GetLastError()
    print("=" * 60)
    print("ERROR: Failed to install KEYBOARD hook!")
    print(f"Windows Error Code: {error_code}")
    if error_code == 5:
        print("ACCESS DENIED - You need to run this script as Administrator")
    elif error_code == 1428:
        print("HOOK INSTALLATION FAILED - Another hook may be interfering")
    else:
        print(f"Unknown error - Google 'Windows error {error_code}'")
    print("=" * 60)
    exit(1)

mouse_hook = user32.SetWindowsHookExW(WH_MOUSE_LL, mouse_ref, None, 0)
if not mouse_hook:
    error_code = kernel32.GetLastError()
    print("=" * 60)
    print("ERROR: Failed to install MOUSE hook!")
    print(f"Windows Error Code: {error_code}")
    if error_code == 5:
        print("ACCESS DENIED - You need to run this script as Administrator")
    elif error_code == 1428:
        print("HOOK INSTALLATION FAILED - Another hook may be interfering")
    else:
        print(f"Unknown error - Google 'Windows error {error_code}'")
    print("=" * 60)
    # Clean up keyboard hook before exiting
    user32.UnhookWindowsHookEx(kbd_hook)
    exit(1)

print("=" * 60)
print("INPUT SOURCE DIAGNOSTIC TEST")
print("=" * 60)
print("\n[HARDWARE] = Real local input (Mac via QEMU)")
print("[INJECTED] = Synthetic input (SendInput/malware)")
print("\nPress keys and click mouse to test...")
print("To exit: Close this window or use Task Manager to kill python.exe")
print("\n⚠️  EMERGENCY TIMEOUT: Script will auto-exit in 60 seconds\n")

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
    if kbd_hook:
        user32.UnhookWindowsHookEx(kbd_hook)
    if mouse_hook:
        user32.UnhookWindowsHookEx(mouse_hook)
    print("Hooks removed.")
