"""
Configuration for Blackhole Input Firewall Service
"""

from pynput.keyboard import Key

# ============================================================================
# HOTKEY CONFIGURATION
# ============================================================================

# Hotkey system removed - firewall is controlled by service start/stop only
# When service is running, firewall is ACTIVE (blocks remote input)
# When service is stopped, firewall is INACTIVE (allows all input)

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
