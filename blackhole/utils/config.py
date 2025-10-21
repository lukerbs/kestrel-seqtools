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

# Maximum queue size for decision queue (Raw Input → Hooks communication)
MAX_QUEUE_SIZE = 1000

# Identifiers used to whitelist hypervisor's virtual input devices.
# Add substrings from your VM's virtual device names if they are not detected.
# Common identifiers:
# - UTM/QEMU: "HID", "VID_0627", "QEMU"
# - VMware: "VMWARE"
# - VirtualBox: "VBOX", "VirtualBox"
# - Hyper-V: "VMBUS", "Hyper-V"
HYPERVISOR_IDENTIFIERS = [
    "HID",  # UTM/QEMU devices show as generic HID devices
    "VID_0627",  # QEMU vendor ID
    "QEMU",  # QEMU identifier
]
