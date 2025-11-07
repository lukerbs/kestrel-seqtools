"""
AnyDesk Finder - Discovers AnyDesk.exe location on the system
Ported from anytime/launcher.py with 3-tier discovery strategy
"""

import os
import subprocess
import sys


class AnyDeskFinder:
    """
    Finds the AnyDesk.exe installation on Windows.
    Uses a 3-tier discovery strategy for maximum reliability.
    """

    @staticmethod
    def find_anydesk(log_func=None):
        """
        Find AnyDesk.exe using 3-tier strategy.

        Args:
            log_func: Optional logging function

        Returns:
            str: Full path to AnyDesk.exe, or None if not found
        """
        log = log_func if log_func else lambda msg: None

        log("[ANYDESK_FINDER] Starting 3-tier discovery...")

        # Tier 1: Check running processes
        log("[ANYDESK_FINDER] Tier 1: Checking running processes...")
        path = AnyDeskFinder._find_in_running_processes(log)
        if path:
            log(f"[ANYDESK_FINDER] Found via running process: {path}")
            return path

        # Tier 2: Check common installation paths
        log("[ANYDESK_FINDER] Tier 2: Checking common paths...")
        path = AnyDeskFinder._find_in_common_paths(log)
        if path:
            log(f"[ANYDESK_FINDER] Found in common path: {path}")
            return path

        # Tier 3: Shallow recursive search
        log("[ANYDESK_FINDER] Tier 3: Shallow recursive search...")
        path = AnyDeskFinder._find_via_shallow_search(log)
        if path:
            log(f"[ANYDESK_FINDER] Found via shallow search: {path}")
            return path

        log("[ANYDESK_FINDER] AnyDesk.exe not found")
        return None

    @staticmethod
    def _find_in_running_processes(log_func):
        """
        Tier 1: Check if AnyDesk.exe is currently running.
        If found, get its full path via wmic.
        """
        try:
            # Check if AnyDesk.exe is running
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq AnyDesk.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )

            if result.returncode == 0 and "AnyDesk.exe" in result.stdout:
                log_func("[ANYDESK_FINDER] AnyDesk.exe is running, getting path...")

                # Get full path using wmic
                wmic_result = subprocess.run(
                    ["wmic", "process", "where", "name='AnyDesk.exe'", "get", "ExecutablePath", "/format:list"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )

                if wmic_result.returncode == 0:
                    for line in wmic_result.stdout.split("\n"):
                        if line.startswith("ExecutablePath="):
                            path = line.split("=", 1)[1].strip()
                            if path and os.path.exists(path):
                                return path

        except Exception as e:
            log_func(f"[ANYDESK_FINDER] Error checking running processes: {e}")

        return None

    @staticmethod
    def _find_in_common_paths(log_func):
        """
        Tier 2: Check common installation paths.
        """
        common_paths = [
            # Installed version (default)
            r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
            r"C:\Program Files\AnyDesk\AnyDesk.exe",
            # Portable version (user profile)
            os.path.join(os.getenv("APPDATA", ""), "AnyDesk", "AnyDesk.exe"),
            os.path.join(os.getenv("LOCALAPPDATA", ""), "AnyDesk", "AnyDesk.exe"),
            # Desktop (common portable location)
            os.path.join(os.path.expanduser("~"), "Desktop", "AnyDesk.exe"),
            # Downloads (common portable location)
            os.path.join(os.path.expanduser("~"), "Downloads", "AnyDesk.exe"),
        ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        return None

    @staticmethod
    def _find_via_shallow_search(log_func):
        """
        Tier 3: Shallow recursive search of common directories.
        Limited depth to avoid performance issues.
        """
        search_roots = [
            r"C:\Program Files (x86)",
            r"C:\Program Files",
            os.path.expanduser("~"),
        ]

        max_depth = 3  # Limit recursion depth

        for root in search_roots:
            if not os.path.exists(root):
                continue

            log_func(f"[ANYDESK_FINDER] Searching {root} (max depth: {max_depth})...")

            try:
                path = AnyDeskFinder._recursive_search(root, max_depth)
                if path:
                    return path
            except Exception as e:
                log_func(f"[ANYDESK_FINDER] Error searching {root}: {e}")

        return None

    @staticmethod
    def _recursive_search(directory, max_depth, current_depth=0):
        """
        Recursively search for AnyDesk.exe with depth limit.
        """
        if current_depth > max_depth:
            return None

        try:
            for entry in os.scandir(directory):
                try:
                    if entry.is_file() and entry.name.lower() == "anydesk.exe":
                        return entry.path
                    elif entry.is_dir() and not entry.is_symlink():
                        # Skip known large directories
                        skip_dirs = {"Windows", "System32", "WinSxS", "node_modules", ".git"}
                        if entry.name not in skip_dirs:
                            result = AnyDeskFinder._recursive_search(entry.path, max_depth, current_depth + 1)
                            if result:
                                return result
                except (PermissionError, OSError):
                    # Skip inaccessible directories
                    continue

        except (PermissionError, OSError):
            pass

        return None
