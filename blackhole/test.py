"""
Third-Party Process Enumerator
Identifies all non-Microsoft/non-Windows processes currently running.
This helps identify which processes would be hooked by Blackhole's universal blocking.
"""

import psutil
import sys
from pathlib import Path


# Windows system directories (Microsoft processes typically live here)
SYSTEM_PATHS = [
    "c:\\windows\\",
    "c:\\program files\\windows",
    "c:\\program files (x86)\\windows",
]

# Known Microsoft process names (case-insensitive)
MICROSOFT_PROCESS_NAMES = {
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "winlogon.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "sihost.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "fontdrvhost.exe",
    "conhost.exe",
    "dllhost.exe",
    "wudfhost.exe",
    "spoolsv.exe",
    "audiodg.exe",
    "wlanext.exe",
    "dashost.exe",
    "msedge.exe",
    "microsoftedgeupdate.exe",
    "onedrive.exe",
}


def is_microsoft_process(proc_info):
    """
    Determine if a process is a Microsoft/Windows system process.

    Args:
        proc_info: dict with 'name' and 'exe' keys

    Returns:
        bool: True if Microsoft process, False if third-party
    """
    name = proc_info.get("name", "").lower()
    exe_path = proc_info.get("exe", "")

    # Check if it's a known Microsoft process name
    if name in MICROSOFT_PROCESS_NAMES:
        return True

    # Check if it's in a Windows system directory
    if exe_path:
        exe_lower = exe_path.lower()
        for sys_path in SYSTEM_PATHS:
            if sys_path in exe_lower:
                return True

    return False


def get_third_party_processes():
    """
    Get all third-party (non-Microsoft) processes.

    Returns:
        list: List of dicts with process info (pid, name, exe)
    """
    third_party = []

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = proc.info

            # Skip if no exe path (kernel processes, etc.)
            if not info["exe"]:
                continue

            # Skip Microsoft processes
            if is_microsoft_process(info):
                continue

            third_party.append({"pid": info["pid"], "name": info["name"], "exe": info["exe"]})

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process terminated or we don't have permission
            continue

    return third_party


def main():
    print("=" * 80)
    print("THIRD-PARTY PROCESS ENUMERATION")
    print("=" * 80)
    print("\nScanning for non-Microsoft processes...\n")

    third_party = get_third_party_processes()

    if not third_party:
        print("No third-party processes found.")
        return

    print(f"Found {len(third_party)} third-party process(es):\n")
    print(f"{'PID':<8} {'NAME':<30} {'PATH'}")
    print("-" * 80)

    for proc in sorted(third_party, key=lambda p: p["name"].lower()):
        print(f"{proc['pid']:<8} {proc['name']:<30} {proc['exe']}")

    print("\n" + "=" * 80)
    print(f"Total: {len(third_party)} third-party processes")
    print("=" * 80)
    print("\nThese are the processes that Blackhole would hook with universal blocking.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)
