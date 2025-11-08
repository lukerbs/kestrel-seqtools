import ctypes
from ctypes import wintypes

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


def keyboard_callback(nCode, wParam, lParam):
    try:
        if nCode == HC_ACTION:
            kbd = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            is_injected = kbd.flags & 0x00000010
            source = "[INJECTED]" if is_injected else "[HARDWARE]"
            print(f"KEYBOARD: {source} flags={kbd.flags:#010x}")
    except:
        pass  # Don't let exceptions block input

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
    except:
        pass  # Don't let exceptions block input

    return user32.CallNextHookEx(None, nCode, wParam, lParam)


kbd_ref = HOOKPROC(keyboard_callback)
mouse_ref = HOOKPROC(mouse_callback)

hInstance = kernel32.GetModuleHandleW(None)
kbd_hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, kbd_ref, hInstance, 0)
mouse_hook = user32.SetWindowsHookExW(WH_MOUSE_LL, mouse_ref, hInstance, 0)

print("=" * 60)
print("INPUT SOURCE DIAGNOSTIC TEST")
print("=" * 60)
print("\n[HARDWARE] = Real local input (Mac via QEMU)")
print("[INJECTED] = Synthetic input (SendInput/malware)")
print("\nPress keys and click mouse to test...")
print("Press Ctrl+C to exit\n")

# Message loop
msg = wintypes.MSG()
while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
    user32.TranslateMessage(ctypes.byref(msg))
    user32.DispatchMessageW(ctypes.byref(msg))
