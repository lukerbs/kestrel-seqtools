"""
Blackhole Universal Blocking - Whitelist Test
Tests the whitelist logic to identify which processes would be hooked.

Uses digital signature verification to automatically whitelist ALL Microsoft processes,
plus explicit whitelisting for virtualization tools and honeypot-specific applications.

Any process NOT on the whitelist will be hooked and have its input blocked.
"""

import psutil
import sys
import subprocess


# Known Microsoft process names (case-insensitive)
# Used as fallback if digital signature check fails
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
    "memcompression",
}

# Virtualization tools (QEMU/UTM/SPICE) - explicitly trusted
VIRTUALIZATION_PROCESS_NAMES = {
    "qemu-ga.exe",
    "vdagent.exe",
    "vdservice.exe",
    "blnsvr.exe",
}

# Honeypot-specific trusted tools
HONEYPOT_PROCESS_NAMES = {
    "mullvad vpn.exe",
    "mullvad-daemon.exe",
    "netservice.exe",  # Fake bank site
    "python.exe",  # Your scripts
}


def is_signed_by_microsoft(exe_path):
    """
    Check if an executable is digitally signed by Microsoft Corporation.
    Uses PowerShell's Get-AuthenticodeSignature to verify the code signing certificate.

    Args:
        exe_path: Full path to the executable

    Returns:
        bool: True if signed by Microsoft, False otherwise
    """
    if not exe_path:
        return False

    try:
        # Use PowerShell to check the digital signature
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"(Get-AuthenticodeSignature '{exe_path}').SignerCertificate.Subject",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=2, creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode == 0:
            subject = result.stdout.strip()
            # Check if certificate subject contains "Microsoft Corporation"
            if "Microsoft Corporation" in subject or "Microsoft Windows" in subject:
                return True

    except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception):
        # If signature check fails, fall back to other checks
        pass

    return False


def is_whitelisted_process(proc_info):
    """
    Determine if a process should be whitelisted (trusted).
    Uses digital signature verification for Microsoft processes,
    and explicit name matching for virtualization/honeypot tools.

    Args:
        proc_info: dict with 'name' and 'exe' keys

    Returns:
        bool: True if whitelisted (trusted), False if should be hooked
    """
    name = proc_info.get("name", "").lower()
    exe_path = proc_info.get("exe", "")

    # 1. Check if it's a virtualization tool (QEMU/UTM/SPICE)
    if name in VIRTUALIZATION_PROCESS_NAMES:
        return True

    # 2. Check if it's a honeypot-specific tool
    if name in HONEYPOT_PROCESS_NAMES:
        return True

    # 3. Check digital signature for Microsoft processes (most reliable)
    if exe_path and is_signed_by_microsoft(exe_path):
        return True

    # 4. Fallback: Check if it's a known Microsoft process name
    if name in MICROSOFT_PROCESS_NAMES:
        return True

    # 5. Fallback: Check if it's in protected Windows system directories
    #    (Only trust truly protected paths - not Program Files)
    if exe_path:
        exe_lower = exe_path.lower()
        protected_paths = [
            "c:\\windows\\system32\\",
            "c:\\windows\\syswow64\\",
            "c:\\windows\\system\\",
        ]
        for sys_path in protected_paths:
            if sys_path in exe_lower:
                return True

    # NOT whitelisted - should be hooked
    return False


def get_non_whitelisted_processes():
    """
    Get all processes that are NOT whitelisted (should be hooked).

    Returns:
        list: List of dicts with process info (pid, name, exe, reason)
    """
    non_whitelisted = []

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = proc.info

            # Skip if no exe path (kernel processes, etc.)
            if not info["exe"]:
                continue

            # Skip whitelisted processes
            if is_whitelisted_process(info):
                continue

            # This process should be hooked!
            non_whitelisted.append({"pid": info["pid"], "name": info["name"], "exe": info["exe"]})

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process terminated or we don't have permission
            continue

    return non_whitelisted


def main():
    print("=" * 80)
    print("BLACKHOLE UNIVERSAL BLOCKING - PROCESS WHITELIST TEST")
    print("=" * 80)
    print("\nScanning all processes...")
    print("Whitelisted: Microsoft (signed), Virtualization tools, Honeypot tools")
    print("NOT Whitelisted: Everything else (will be hooked)\n")

    non_whitelisted = get_non_whitelisted_processes()

    if not non_whitelisted:
        print("✅ All processes are whitelisted! No processes would be hooked.")
        return

    print(f"⚠️  Found {len(non_whitelisted)} process(es) that WOULD BE HOOKED:\n")
    print(f"{'PID':<8} {'NAME':<30} {'PATH'}")
    print("-" * 80)

    for proc in sorted(non_whitelisted, key=lambda p: p["name"].lower()):
        print(f"{proc['pid']:<8} {proc['name']:<30} {proc['exe']}")

    print("\n" + "=" * 80)
    print(f"Total: {len(non_whitelisted)} process(es) would be hooked")
    print("=" * 80)
    print("\n✅ Whitelist Logic:")
    print("   - Microsoft-signed executables (verified by certificate)")
    print("   - QEMU/UTM/SPICE virtualization tools")
    print("   - Honeypot-specific tools (Mullvad, netservice.exe, python.exe)")
    print("\n❌ These processes would have ALL input tagged and blocked by Blackhole.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)
