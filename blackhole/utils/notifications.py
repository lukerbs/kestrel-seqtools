"""
Windows notification popups for dev mode feedback
"""

import ctypes


def show_activated_popup():
    """
    Show popup notification when firewall is activated (blocking remote input).
    Uses native Windows MessageBox for consistency with receiver.py buddy system.
    """
    title = "Input Firewall - ACTIVE"
    message = (
        "Remote desktop input is now BLOCKED.\n\n"
        "Your host input (from Mac) still works.\n\n"
        "Press Command+Shift+F again to deactivate."
    )

    # Display native Windows message box with information icon (0x40)
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)


def show_deactivated_popup():
    """
    Show popup notification when firewall is deactivated (allowing all input).
    Uses native Windows MessageBox for consistency with receiver.py buddy system.
    """
    title = "Input Firewall - INACTIVE"
    message = (
        "Remote desktop input is now ALLOWED.\n\n"
        "All input is passing through normally.\n\n"
        "Press Command+Shift+F to activate blocking."
    )

    # Display native Windows message box with information icon (0x40)
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
