"""
Whitelist/Blacklist Manager with Hash Verification
Manages application whitelisting with SHA256 hash verification and Microsoft signature checking.
"""

import os
import json
import hashlib
import subprocess
import psutil
from datetime import datetime


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
        Create initial whitelist from all running processes.
        Called on first run when whitelist.json doesn't exist.

        Args:
            blacklist_seed: List of process names to seed the blacklist (e.g., ["AnyDesk.exe"])
        """
        self._log("[WHITELIST] Creating first-run baseline...")
        self._log("[WHITELIST] This may take a minute...")

        whitelisted_count = 0
        blacklisted_count = 0

        # Enumerate all running processes
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = proc.info["name"]
                exe_path = proc.info.get("exe")

                # Skip kernel/system processes without valid executable paths
                if not exe_path or not os.path.isfile(exe_path):
                    continue

                # Check if this process should be blacklisted
                if name in blacklist_seed:
                    self._add_to_blacklist_internal(name, exe_path, "Remote access tool (pre-seeded)")
                    blacklisted_count += 1
                    self._log(f"[WHITELIST] Blacklisted: {name}")
                else:
                    # Add to whitelist
                    self._add_to_whitelist_internal(name, exe_path)
                    whitelisted_count += 1

                    # Progress indicator every 10 processes
                    if whitelisted_count % 10 == 0:
                        self._log(f"[WHITELIST] Processed {whitelisted_count} processes...", end="\r")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Save to disk
        self._save_whitelist()
        self._save_blacklist()

        self._log(f"[WHITELIST] Baseline complete!")
        self._log(f"[WHITELIST] Whitelisted: {whitelisted_count} processes")
        self._log(f"[WHITELIST] Blacklisted: {blacklisted_count} processes")

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
