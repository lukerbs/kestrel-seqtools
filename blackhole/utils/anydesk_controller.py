"""
AnyDesk Controller - Manages AnyDesk CLI operations
Launches reverse connections to scammer machines
"""

import subprocess
import sys


class AnyDeskController:
    """
    Controls AnyDesk via command-line interface.
    Used to initiate reverse connections to scammers.
    """

    def __init__(self, log_func=None):
        """
        Initialize the controller.

        Args:
            log_func: Optional logging function
        """
        self._log = log_func if log_func else lambda msg: None

    def initiate_connection(self, anydesk_exe_path, target_id):
        """
        Launch AnyDesk connection to target ID.
        Non-blocking: Returns immediately after launching.

        Args:
            anydesk_exe_path: Full path to AnyDesk.exe
            target_id: Target AnyDesk ID (9-10 digit number)

        Returns:
            int or None: PID of spawned process if successful, None otherwise
        """
        if not anydesk_exe_path:
            self._log("[ANYDESK_CONTROLLER] Error: AnyDesk path not provided")
            return None

        try:
            self._log(f"[ANYDESK_CONTROLLER] Launching connection to {target_id}...")

            # Launch AnyDesk with target ID as argument
            # This opens the AnyDesk connection window
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

            proc = subprocess.Popen(
                [anydesk_exe_path, target_id],
                creationflags=creationflags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            self._log(f"[ANYDESK_CONTROLLER] Connection window launched for {target_id} (PID: {proc.pid})")
            return proc.pid

        except FileNotFoundError:
            self._log(f"[ANYDESK_CONTROLLER] Error: AnyDesk.exe not found at {anydesk_exe_path}")
            return None
        except Exception as e:
            self._log(f"[ANYDESK_CONTROLLER] Error launching connection: {e}")
            return None

    def set_unattended_password(self, anydesk_exe_path, password):
        """
        Set AnyDesk unattended access password (optional).
        This is useful for automating incoming connections.

        Args:
            anydesk_exe_path: Full path to AnyDesk.exe
            password: Password to set

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self._log("[ANYDESK_CONTROLLER] Setting unattended password...")

            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

            result = subprocess.run(
                [anydesk_exe_path, "--set-password", password],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=creationflags,
            )

            if result.returncode == 0:
                self._log("[ANYDESK_CONTROLLER] Password set successfully")
                return True
            else:
                self._log(f"[ANYDESK_CONTROLLER] Failed to set password: {result.stderr}")
                return False

        except Exception as e:
            self._log(f"[ANYDESK_CONTROLLER] Error setting password: {e}")
            return False
