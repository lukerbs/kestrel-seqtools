"""
Configuration for Blackhole Input Firewall Service
"""

# ============================================================================
# SERVICE CONFIGURATION
# ============================================================================

# Service name for Task Scheduler
SERVICE_NAME = "blackhole"

# Executable name
EXE_NAME = "blackhole.exe"

# Default state on startup (True = firewall ON, block remote input)
DEFAULT_FIREWALL_STATE = True

# ============================================================================
# API HOOKING CONFIGURATION
# ============================================================================

# Magic tag value used to mark input from hooked remote desktop processes
# This value is written to dwExtraInfo field of INPUT structures
MAGIC_TAG = 0xDEADBEEF

# Target processes to hook (remote desktop applications)
# The service will automatically detect and hook SendInput() in these processes
TARGET_PROCESSES = [
    "AnyDesk.exe",
    "TeamViewer.exe",
    "RemotePC.exe",
    "Chrome Remote Desktop.exe",
    "LogMeIn.exe",
    "GoToMyPC.exe",
    "Splashtop.exe",
]

# ============================================================================
# PROCESS MONITOR CONFIGURATION
# ============================================================================

# How often to scan for target processes (seconds)
PROCESS_SCAN_INTERVAL = 2.0

# ============================================================================
# HOTKEY CONFIGURATION
# ============================================================================

# Hotkey to toggle firewall on/off (Ctrl+Shift+F)
# Format: pynput hotkey string format
TOGGLE_HOTKEY = "<ctrl>+<shift>+f"
