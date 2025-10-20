"""
Shell command execution feature
"""

import subprocess
import platform
import socket
import sys
from utils.protocol import send_text
from utils.config import END_MARKER


# Use the system's output encoding (check if sys.stdout exists for --noconsole mode)
DECODING = sys.stdout.encoding if sys.stdout and sys.stdout.encoding else "utf-8"


def execute_command_stream(command: str, client_socket: socket.socket, working_dir: str = None) -> str:
    """
    Executes a command and streams output back through the socket.

    Shell used:
    - Windows: PowerShell (powershell.exe)
    - Unix/Linux/macOS: Default shell (/bin/sh)

    Automatically appends directory tracking commands to maintain working directory:
    - Windows PowerShell: '; Get-Location | Select-Object -ExpandProperty Path'
    - Unix: '&& pwd'

    The directory output is hidden from the sender (used only for internal tracking).
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
    if system == "Windows":
        # PowerShell uses semicolon for command chaining and Get-Location for pwd
        pwd_command = "Get-Location | Select-Object -ExpandProperty Path"
        command_separator = ";"
    else:
        pwd_command = "pwd"
        command_separator = "&&"

    # For clear commands, don't append pwd tracking (it causes issues)
    # Just return the current working_dir unchanged
    if is_clear_command:
        command_to_run = command
        track_directory = False
    else:
        command_to_run = f"{command} {command_separator} {pwd_command}"
        track_directory = True

    try:
        # Configure shell execution based on OS
        if system == "Windows":
            # Use PowerShell on Windows
            # PowerShell requires commands to be passed with -Command flag
            process = subprocess.Popen(
                ["powershell.exe", "-Command", command_to_run],
                shell=False,  # shell=False when passing command as list
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=working_dir,
            )
        else:
            # Use default shell on Unix (shell=True)
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
        error_msg = f"\n[error: {e}]\n"
        # Send error to sender (don't print locally)
        try:
            send_text(client_socket, error_msg)
        except (socket.error, OSError, BrokenPipeError):
            pass  # Socket already closed, nothing we can do

        # On error, return the previous working_dir unchanged
        return working_dir
