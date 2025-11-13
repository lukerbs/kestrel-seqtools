"""
Whitelist/Blacklist Manager with Hash Verification
Manages application whitelisting with SHA256 hash verification and Microsoft signature checking.
"""

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import psutil
from tqdm import tqdm

from ..config import BASELINE_SCAN_DIRECTORIES, BASELINE_SKIP_DIRS


class WhitelistManager:
    """
    Manages whitelist and blacklist JSON files with hash-based verification.
    Implements cryptographic trust for Microsoft-signed apps and explicit trust for others.
    """

    def __init__(self, data_dir, log_func=None):
        """
        Initialize the whitelist manager.

        Args:
            data_dir: Directory where whitelist.json and blacklist.json are stored
            log_func: Optional logging function
        """
        self._log = log_func if log_func else lambda msg: None
        self.data_dir = data_dir
        self.whitelist_path = os.path.join(data_dir, "whitelist.json")
        self.blacklist_path = os.path.join(data_dir, "blacklist.json")

        # In-memory caches
        # Changed to use normalized path as key for unique identification
        self.whitelist = {}  # {normalized_path: {name, hash, path, signed_by, added}}
        self.blacklist = {}  # {normalized_path: {name, hash, path, reason, added}}

        # Ensure data directory exists
        os.makedirs(data_dir, exist_ok=True)

        # Load existing JSON files if they exist
        self._load_whitelist()
        self._load_blacklist()

    def _load_whitelist(self):
        """Load whitelist from JSON file"""
        if os.path.exists(self.whitelist_path):
            try:
                with open(self.whitelist_path, "r", encoding="utf-8") as f:
                    self.whitelist = json.load(f)
                self._log(f"[WHITELIST] Loaded {len(self.whitelist)} whitelisted processes")
            except Exception as e:
                self._log(f"[WHITELIST] Error loading whitelist: {e}")
                self.whitelist = {}

    def _load_blacklist(self):
        """Load blacklist from JSON file"""
        if os.path.exists(self.blacklist_path):
            try:
                with open(self.blacklist_path, "r", encoding="utf-8") as f:
                    self.blacklist = json.load(f)
                self._log(f"[WHITELIST] Loaded {len(self.blacklist)} blacklisted processes")
            except Exception as e:
                self._log(f"[WHITELIST] Error loading blacklist: {e}")
                self.blacklist = {}

    def _save_whitelist(self):
        """Save whitelist to JSON file"""
        try:
            with open(self.whitelist_path, "w", encoding="utf-8") as f:
                json.dump(self.whitelist, f, indent=2)
        except Exception as e:
            self._log(f"[WHITELIST] Error saving whitelist: {e}")

    def _save_blacklist(self):
        """Save blacklist to JSON file"""
        try:
            with open(self.blacklist_path, "w", encoding="utf-8") as f:
                json.dump(self.blacklist, f, indent=2)
        except Exception as e:
            self._log(f"[WHITELIST] Error saving blacklist: {e}")

    def _normalize_path(self, file_path):
        """
        Normalize a file path for consistent comparison.

        Args:
            file_path: Path to normalize

        Returns:
            str: Normalized lowercase path
        """
        if not file_path:
            return None
        try:
            # Use os.path.normpath to resolve .. and .
            # Convert to lowercase for case-insensitive comparison (Windows)
            return os.path.normpath(file_path).lower()
        except Exception:
            return file_path.lower()

    def _calculate_hash(self, file_path):
        """
        Calculate SHA256 hash of a file.

        Args:
            file_path: Path to the executable

        Returns:
            str: SHA256 hash in hexadecimal, or None if error
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read in 64KB chunks for efficiency
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self._log(f"[WHITELIST] Error calculating hash for {file_path}: {e}")
            return None

    def _check_microsoft_signature(self, exe_path):
        """
        Check if an executable is digitally signed by Microsoft Corporation.

        Args:
            exe_path: Full path to the executable

        Returns:
            str: "Microsoft Corporation" if signed by Microsoft, None otherwise
        """
        if not exe_path:
            return None

        try:
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-AuthenticodeSignature '{exe_path}').SignerCertificate.Subject",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1.0,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            if result.returncode == 0:
                subject = result.stdout.strip()
                if "Microsoft Corporation" in subject or "Microsoft Windows" in subject:
                    return "Microsoft Corporation"

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception):
            pass

        return None

    def first_run_baseline(self, blacklist_seed):
        """
        Create initial whitelist from ALL installed executables via filesystem scan.
        Called on first run when whitelist.json doesn't exist.

        Two-phase approach:
        1. Discover all .exe files (fast enumeration)
        2. Process them in parallel with progress bar (hash calculation + signature check)

        Args:
            blacklist_seed: List of process names to seed the blacklist (e.g., ["AnyDesk.exe"])
        """
        self._log("[WHITELIST] Creating first-run baseline...")
        self._log("[WHITELIST] Phase 1: Discovering all executables...")

        # Build complete list of directories to scan
        scan_dirs = list(BASELINE_SCAN_DIRECTORIES)

        # Add user-specific directories
        try:
            scan_dirs.append(os.path.expandvars(r"%APPDATA%"))
            scan_dirs.append(os.path.expandvars(r"%LOCALAPPDATA%"))
        except Exception:
            pass  # Skip if env vars not available

        # PHASE 1: Enumerate all .exe files
        exe_files_to_process = []  # List of (filename, full_path) tuples
        seen_paths = set()  # Track normalized paths to avoid duplicates

        for directory in scan_dirs:
            if not os.path.exists(directory):
                self._log(f"[WHITELIST] Skipping non-existent: {directory}")
                continue

            self._log(f"[WHITELIST] Enumerating: {directory}")

            try:
                for root, dirs, files in os.walk(directory):
                    # Filter out skip directories (modifies dirs in-place)
                    filtered_dirs = []
                    for d in dirs:
                        dir_lower = d.lower()

                        # Special handling for windowsapps:
                        # Skip user-level %LOCALAPPDATA%\Microsoft\WindowsApps (reparse points)
                        # But NOT C:\Program Files\WindowsApps (legitimate Store apps)
                        if dir_lower == "windowsapps":
                            # Check if we're in the user's AppData\Local\Microsoft path
                            root_lower = root.lower()
                            if "appdata\\local\\microsoft" in root_lower or "appdata/local/microsoft" in root_lower:
                                # This is the user-level WindowsApps with reparse points - SKIP
                                self._log(f"[WHITELIST] Skipping user-level WindowsApps: {os.path.join(root, d)}")
                                continue
                            # Otherwise it's C:\Program Files\WindowsApps - DON'T skip

                        # Apply standard skip list
                        if dir_lower not in BASELINE_SKIP_DIRS:
                            filtered_dirs.append(d)

                    dirs[:] = filtered_dirs

                    for file in files:
                        # Only process .exe files
                        if not file.lower().endswith(".exe"):
                            continue

                        exe_path = os.path.join(root, file)
                        normalized_path = self._normalize_path(exe_path)

                        # Skip if already seen (avoid duplicates)
                        if normalized_path in seen_paths:
                            continue

                        # Verify file is accessible
                        if not os.path.isfile(exe_path):
                            continue

                        seen_paths.add(normalized_path)
                        exe_files_to_process.append((file, exe_path))

            except (PermissionError, OSError) as e:
                self._log(f"[WHITELIST] Error enumerating {directory}: {e}")
                continue

        total_files = len(exe_files_to_process)
        self._log(f"[WHITELIST] Found {total_files} unique executables")

        # Determine optimal worker count (CPU cores * 2 for I/O bound tasks)
        max_workers = min(multiprocessing.cpu_count() * 2, 16)  # Cap at 16
        self._log(f"[WHITELIST] Phase 2: Processing with {max_workers} parallel workers...")
        self._log(f"[WHITELIST] This may take 2-5 minutes...")

        # PHASE 2: Process all discovered executables in parallel with progress bar
        results = []  # Store results for later processing

        def process_executable(file_info):
            """Worker function to process one executable (hash + signature check)"""
            file, exe_path = file_info
            try:
                # Calculate hash
                file_hash = self._calculate_hash(exe_path)
                if not file_hash:
                    return None

                # Check digital signature
                signed_by = self._check_microsoft_signature(exe_path)

                return {
                    "name": file,
                    "path": exe_path,
                    "hash": file_hash,
                    "signed_by": signed_by,
                    "success": True,
                }
            except (PermissionError, OSError):
                return None

        # Process files in parallel with progress bar
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(process_executable, file_info): file_info for file_info in exe_files_to_process
            }

            # Process results as they complete
            # Disable progress bar if stdout is not available (headless PyInstaller)
            with tqdm(
                total=total_files,
                desc="Processing",
                unit="exe",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                disable=sys.stdout is None,  # Disable if stdout is None (headless mode)
            ) as pbar:
                for future in as_completed(future_to_file):
                    file_info = future_to_file[future]
                    file, exe_path = file_info

                    try:
                        result = future.result()
                        if result:
                            results.append((file, result, file in blacklist_seed))

                            if len(results) % 10 == 0:
                                pbar.set_postfix_str(f"Processing: {file[:40]}")

                        pbar.update(1)

                    except Exception as e:
                        pbar.update(1)
                        continue

        # Now add all results to whitelist/blacklist (fast, no I/O)
        self._log("\n[WHITELIST] Finalizing whitelist/blacklist...")
        whitelisted_count = 0
        blacklisted_count = 0

        for file, result, is_blacklisted in results:
            normalized_path = self._normalize_path(result["path"])

            if is_blacklisted:
                # Add to blacklist dict
                self.blacklist[normalized_path] = {
                    "name": result["name"],
                    "hash": result["hash"],
                    "path": result["path"],
                    "reason": "Remote access tool (pre-seeded)",
                    "added": datetime.now().isoformat(),
                }
                blacklisted_count += 1
            else:
                # Add to whitelist dict
                self.whitelist[normalized_path] = {
                    "name": result["name"],
                    "hash": result["hash"],
                    "path": result["path"],
                    "signed_by": result["signed_by"],
                    "added": datetime.now().isoformat(),
                }
                whitelisted_count += 1

        # Save to disk
        self._log("[WHITELIST] Saving to disk...")
        self._save_whitelist()
        self._save_blacklist()

        self._log(f"[WHITELIST] Baseline complete!")
        self._log(f"[WHITELIST] Whitelisted: {whitelisted_count} executables")
        self._log(f"[WHITELIST] Blacklisted: {blacklisted_count} executables")
        self._log(f"[WHITELIST] Total unique executables processed: {total_files}")

    def _add_to_whitelist_internal(self, process_name, exe_path):
        """Internal method to add to whitelist without saving (used during baseline)"""
        file_hash = self._calculate_hash(exe_path)
        if not file_hash:
            return

        signed_by = self._check_microsoft_signature(exe_path)

        # Use normalized path as key for unique identification
        normalized_path = self._normalize_path(exe_path)
        if not normalized_path:
            return

        self.whitelist[normalized_path] = {
            "name": process_name,
            "hash": file_hash,
            "path": exe_path,
            "signed_by": signed_by,
            "added": datetime.now().isoformat(),
        }

    def _add_to_blacklist_internal(self, process_name, exe_path, reason):
        """Internal method to add to blacklist without saving (used during baseline)"""
        file_hash = self._calculate_hash(exe_path)

        # Use normalized path as key for unique identification
        normalized_path = self._normalize_path(exe_path)
        if not normalized_path:
            return

        self.blacklist[normalized_path] = {
            "name": process_name,
            "hash": file_hash if file_hash else "unknown",
            "path": exe_path,
            "reason": reason,
            "added": datetime.now().isoformat(),
        }

    def is_whitelisted(self, process_name, exe_path):
        """
        Check if a process is in the whitelist.

        Args:
            process_name: Name of the process (e.g., "explorer.exe")
            exe_path: Full path to the executable

        Returns:
            bool: True if whitelisted, False otherwise
        """
        normalized_path = self._normalize_path(exe_path)
        return normalized_path in self.whitelist if normalized_path else False

    def is_blacklisted(self, process_name, exe_path):
        """
        Check if a process is in the blacklist.

        Args:
            process_name: Name of the process
            exe_path: Full path to the executable

        Returns:
            bool: True if blacklisted, False otherwise
        """
        normalized_path = self._normalize_path(exe_path)
        return normalized_path in self.blacklist if normalized_path else False

    def verify_hash(self, process_name, exe_path):
        """
        Verify that the hash of a whitelisted process matches the stored hash.
        For Microsoft-signed processes, auto-updates hash if signature is still valid.
        For unsigned processes, returns False on mismatch (requires user decision).

        Args:
            process_name: Name of the process
            exe_path: Current path to the executable

        Returns:
            tuple: (bool: hash_valid, bool: auto_updated)
        """
        normalized_path = self._normalize_path(exe_path)
        if not normalized_path or normalized_path not in self.whitelist:
            return (False, False)

        stored_data = self.whitelist[normalized_path]
        stored_hash = stored_data["hash"]
        stored_path = stored_data["path"]
        signed_by = stored_data.get("signed_by")

        # Verify path matches (should always match since we use path as key, but double-check)
        if self._normalize_path(stored_path) != normalized_path:
            self._log(f"[WHITELIST] Path mismatch for {process_name}: {stored_path} != {exe_path}")
            return (False, False)

        # Calculate current hash
        current_hash = self._calculate_hash(exe_path)
        if not current_hash:
            return (False, False)

        # Hash matches - all good
        if current_hash == stored_hash:
            return (True, False)

        # Hash mismatch - handle based on signature
        if signed_by == "Microsoft Corporation":
            # Microsoft-signed: verify signature again
            current_signature = self._check_microsoft_signature(exe_path)
            if current_signature == "Microsoft Corporation":
                # Signature still valid - auto-update hash
                self._log(f"[WHITELIST] Auto-updating hash for {process_name} at {exe_path} (Microsoft-signed)")
                self.whitelist[normalized_path]["hash"] = current_hash
                self.whitelist[normalized_path]["path"] = exe_path
                self._save_whitelist()
                return (True, True)
            else:
                # Signature invalid - IMPOSTER!
                self._log(f"[WHITELIST] IMPOSTER DETECTED: {process_name} at {exe_path} signature invalid!")
                return (False, False)
        else:
            # Unsigned process with hash mismatch - requires user decision
            return (False, False)

    def add_to_whitelist(self, process_name, exe_path):
        """
        Add a process to the whitelist.

        Args:
            process_name: Name of the process
            exe_path: Path to the executable
        """
        self._log(f"[WHITELIST] Adding to whitelist: {process_name}")
        self._add_to_whitelist_internal(process_name, exe_path)
        self._save_whitelist()

    def add_to_blacklist(self, process_name, exe_path, reason="User denied"):
        """
        Add a process to the blacklist.

        Args:
            process_name: Name of the process
            exe_path: Path to the executable
            reason: Reason for blacklisting
        """
        self._log(f"[WHITELIST] Adding to blacklist: {process_name}")
        self._add_to_blacklist_internal(process_name, exe_path, reason)
        self._save_blacklist()

    def remove_from_whitelist(self, process_name, exe_path):
        """Remove a process from the whitelist"""
        normalized_path = self._normalize_path(exe_path)
        if normalized_path and normalized_path in self.whitelist:
            del self.whitelist[normalized_path]
            self._save_whitelist()
            self._log(f"[WHITELIST] Removed from whitelist: {process_name} at {exe_path}")

    def get_whitelist_count(self):
        """Get number of whitelisted processes"""
        return len(self.whitelist)

    def get_blacklist_count(self):
        """Get number of blacklisted processes"""
        return len(self.blacklist)
