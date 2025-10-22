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
