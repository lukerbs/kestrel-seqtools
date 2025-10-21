"""
Configuration for Blackhole Input Firewall Service
"""

from pynput.keyboard import Key

# ============================================================================
# HOTKEY CONFIGURATION
# ============================================================================

# Toggle hotkey: Command + Shift + F (Mac) → Win + Shift + F (Windows VM)
# Press once to activate firewall (block remote input)
# Press again to deactivate firewall (allow remote input)
TOGGLE_HOTKEY = {Key.cmd_l, Key.shift, "f"}

# ============================================================================
# SERVICE CONFIGURATION
# ============================================================================

# Service name for Task Scheduler
SERVICE_NAME = "blackhole"

# Executable name
EXE_NAME = "blackhole.exe"

# Default state on startup (False = firewall OFF, allow all input)
DEFAULT_FIREWALL_STATE = False

# ============================================================================
# GATEKEEPER CONFIGURATION
# ============================================================================

# Maximum queue size for input events (prevents memory issues)
MAX_QUEUE_SIZE = 1000

# Worker thread timeout (seconds)
WORKER_TIMEOUT = 0.1

# Identifiers used to whitelist hypervisor's virtual input devices.
# Add substrings from your VM's virtual device names if they are not detected.
# Common names:
# - UTM/QEMU: "QEMU"
# - VMware: "VMware"
# - VirtualBox: "VirtualBox"
# - Hyper-V: "Hyper-V"
HYPERVISOR_IDENTIFIERS = [
    "QEMU",  # UTM uses QEMU devices
]
