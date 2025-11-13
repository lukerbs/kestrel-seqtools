"""
System-level utilities for Windows API and hotkeys
"""
# Import all commonly used items from win32_api
from .win32_api import (
    user32,
    kernel32,
    ole32,
)

__all__ = [
    'user32',
    'kernel32',
    'ole32',
]

