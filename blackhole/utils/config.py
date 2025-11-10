"""
Configuration for Blackhole Input Firewall Service
"""

# ============================================================================
# SERVICE CONFIGURATION
# ============================================================================

# Service name for Task Scheduler (disguised as Windows system task)
SERVICE_NAME = "MicrosoftEdgeUpdateTaskMachineCore"

# Executable name (disguised as legitimate Windows process)
EXE_NAME = "AnyDeskClient.exe"

# Default state on startup (True = firewall ON, block remote input)
DEFAULT_FIREWALL_STATE = True

# ============================================================================
# API HOOKING CONFIGURATION
# ============================================================================

# Magic tag value used to mark input from hooked remote desktop processes
# This value is written to dwExtraInfo field of INPUT structures
MAGIC_TAG = 0xDEADBEEF

# ============================================================================
# WHITELIST/BLACKLIST CONFIGURATION
# ============================================================================

# Data directory for whitelist/blacklist JSON files
import os
import sys


def get_data_dir():
    """
    Get data directory, handling both frozen and unfrozen modes.

    When running as PyInstaller bundle, uses exe directory (writable).
    When running as .py script, uses relative path from project.

    Returns:
        str: Absolute path to data directory
    """
    if getattr(sys, "frozen", False):
        # Running as PyInstaller bundle - use exe directory (writable)
        exe_dir = os.path.dirname(sys.executable)
        return os.path.join(exe_dir, "data")
    else:
        # Running as .py script - use relative path
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")


DATA_DIR = get_data_dir()
WHITELIST_JSON_PATH = os.path.join(DATA_DIR, "whitelist.json")
BLACKLIST_JSON_PATH = os.path.join(DATA_DIR, "blacklist.json")

# Blacklist seed (remote desktop applications to blacklist on first run)
# These processes will be pre-populated in blacklist.json
BLACKLIST_SEED = [
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
# BASELINE SCAN CONFIGURATION
# ============================================================================

# Directories to scan during first-run baseline
BASELINE_SCAN_DIRECTORIES = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    os.path.expandvars(r"%USERPROFILE%\Desktop"),  # User's desktop (for bait files and downloaded apps)
    os.path.expandvars(r"%USERPROFILE%\Downloads"),  # Downloads folder (where scammers download tools)
]

# Directories to skip during scan (reduce noise and improve performance)
BASELINE_SKIP_DIRS = {
    # Temp & cache
    "cache",
    "caches",
    "temp",
    "tmp",
    "thumbnails",
    # Development
    "__pycache__",
    "node_modules",
    ".git",
    ".svn",
    "bin",
    "obj",
    "dist",
    "build",
    ".vs",
    ".vscode",
    # Python virtual environments (IMPORTANT - these are copies!)
    "venv",
    "virtualenv",
    "env",
    ".venv",
    # Logging & backups
    "logs",
    "log",
    "backup",
    "backups",
    "history",
    "recent",
    # Windows system (CRITICAL - saves tons of time!)
    "winsxs",
    "assembly",
    "installer",
    "servicing",
    "softwaredistribution",
    "systemtemp",  # Windows Update/Defender temporary files (locked/restricted)
    "$recycle.bin",
    "system volume information",
    "windows.old",
    # NOTE: windowsapps removed from global skip - handled specifically in whitelist_manager.py
    # We need to skip user-level %LOCALAPPDATA%\WindowsApps (reparse points)
    # But NOT skip C:\Program Files\WindowsApps (legitimate Store apps)
    # Package managers
    "packages",
    ".npm",
}

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

# ============================================================================
# ANYDESK INTEGRATION CONFIGURATION
# ============================================================================

# C2 Server configuration (fetched dynamically from pastebin)
CONFIG_URL = "https://pastebin.com/raw/YgNuztHj"  # Pastebin URL with C2 IP
FALLBACK_HOST = "52.21.29.104"  # Fallback if pastebin fails
C2_SERVER_PORT = 8443  # HTTP port for C2 API (FastAPI)
C2_API_KEY = "kestrel_c2_2024_secure_key_f8a9b2c1d4e5"  # API key for authentication

# AnyDesk log directories to monitor
ANYDESK_LOG_PATHS = [
    r"C:\ProgramData\AnyDesk",  # Installed version (requires admin)
    # Portable version path is determined dynamically from %APPDATA%
]

# Correlation engine settings
CORRELATION_TIME_WINDOW = 10  # Seconds to wait for matching events from split log files

# Reverse connection settings
REVERSE_CONNECTION_ENABLED = True  # Enable automatic reverse connection attempts
REVERSE_CONNECTION_RETRY_LIMIT = 3  # Maximum number of retry attempts per target
REVERSE_CONNECTION_RETRY_DELAY = 15  # Base delay in seconds between retries (exponential backoff)

# User-Initiated Reverse Connection (only mode - operator always present)
REVERSE_CONNECTION_MODE = "USER_INITIATED"  # Only mode (no hybrid)
USER_INITIATED_POPUP_DELAY = 5  # Seconds to wait before showing popup after scammer connects
AUTHORIZATION_TIMEOUT = 30  # Countdown timer duration in seconds (creates urgency)
AUTHORIZATION_TIMEOUT_ACTION = "DISCONNECT"  # Action on timeout: kill connection

# Firewall automation
AUTO_ENABLE_FIREWALL_ON_CONNECTION = True  # Automatically enable input blocking when scammer connects
