"""
API Hooker - Uses Frida to hook SendInput() in target processes
"""

import frida
import sys
import os

from ..config import MAGIC_TAG


def _load_frida_script():
    """
    Load the Frida JavaScript hook script from file.
    Returns the script content with MAGIC_TAG substituted.

    Handles both development mode (running as .py) and production mode (running as .exe).
    """
    # Check if running as a PyInstaller bundle
    if getattr(sys, "frozen", False):
        # Running as compiled executable - use PyInstaller's _MEIPASS
        script_dir = os.path.join(sys._MEIPASS, "utils", "scripts")
    else:
        # Running as .py script - use the directory where this file is located
        # Go up two levels (core -> utils) then into scripts
        script_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")

    script_path = os.path.join(script_dir, "frida_hook.js")

    # Read the JavaScript file
    with open(script_path, "r", encoding="utf-8") as f:
        script_content = f.read()

    # Replace the MAGIC_TAG placeholder with the actual value
    script_content = script_content.replace("{{MAGIC_TAG}}", f"'{MAGIC_TAG:#x}'")

    return script_content


class APIHooker:
    """
    Manages Frida-based API hooks on target remote desktop processes.
    Hooks user32.dll!SendInput to tag input with MAGIC_TAG.
    """

    def __init__(self, log_func=None):
        """
        Initialize the API hooker.

        Args:
            log_func: Optional logging function
        """
        self._log = log_func if log_func else lambda msg: None
        self._sessions = {}  # {pid: frida.Session}
        self._scripts = {}  # {pid: frida.Script}

    def hook_process(self, pid, process_name):
        """
        Hook SendInput() in the target process.

        Args:
            pid: Process ID to hook
            process_name: Name of the process (for logging)

        Returns:
            bool: True if successful, False otherwise
        """
        if pid in self._sessions:
            self._log(f"[HOOKER] Already hooked: {process_name} (PID: {pid})")
            return True

        try:
            self._log(f"[HOOKER] Attaching to {process_name} (PID: {pid})...")

            # Attach to the process
            session = frida.attach(pid)

            # Load the Frida JavaScript hook script
            frida_script_content = _load_frida_script()

            # Create and load the Frida script
            script = session.create_script(frida_script_content)
            script.on("message", lambda msg, data: self._on_message(pid, process_name, msg, data))
            script.load()

            # Store session and script
            self._sessions[pid] = session
            self._scripts[pid] = script

            self._log(f"[HOOKER] Successfully hooked {process_name} (PID: {pid})")
            return True

        except frida.ProcessNotFoundError:
            self._log(f"[HOOKER] ERROR: Process {pid} not found")
            return False

        except frida.PermissionDeniedError:
            self._log(f"[HOOKER] ERROR: Permission denied for PID {pid}")
            self._log(f"[HOOKER] NOTE: Frida requires administrator privileges")
            return False

        except Exception as e:
            self._log(f"[HOOKER] ERROR: Failed to hook PID {pid}: {e}")
            return False

    def unhook_process(self, pid):
        """
        Remove hook from process.

        Args:
            pid: Process ID to unhook
        """
        if pid not in self._sessions:
            return

        try:
            # Unload script and detach session
            if pid in self._scripts:
                self._scripts[pid].unload()
                del self._scripts[pid]

            if pid in self._sessions:
                self._sessions[pid].detach()
                del self._sessions[pid]

            self._log(f"[HOOKER] Unhooked PID {pid}")

        except Exception as e:
            self._log(f"[HOOKER] Error unhooking PID {pid}: {e}")

    def unhook_all(self):
        """Remove all hooks"""
        self._log("[HOOKER] Unhooking all processes...")
        for pid in list(self._sessions.keys()):
            self.unhook_process(pid)

    def get_hooked_processes(self):
        """
        Get list of currently hooked process IDs.

        Returns:
            list: List of PIDs
        """
        return list(self._sessions.keys())

    def _on_message(self, pid, process_name, message, data):
        """
        Handle messages from Frida script.

        Args:
            pid: Process ID
            process_name: Process name
            message: Message from Frida
            data: Additional data
        """
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "ready":
                self._log(f"[HOOKER] Hook active in {process_name} (PID: {pid})")

            elif msg_type == "tagged":
                # Only log in verbose mode (too spammy otherwise)
                count = payload.get("count", 0)
                # self._log(f"[HOOKER] Tagged {count} input(s) from {process_name}")

            elif msg_type == "error":
                error_msg = payload.get("message", "Unknown error")
                self._log(f"[HOOKER] Frida error in {process_name} (PID: {pid}): {error_msg}")

        elif message["type"] == "error":
            # Frida internal error
            self._log(f"[HOOKER] Frida internal error in PID {pid}: {message}")
