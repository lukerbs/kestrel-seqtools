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
# HELPER FUNCTIONS
# ============================================================================


def get_current_executable() -> Optional[Tuple[str, str]]:
    """
    Get path to the currently running executable or script.
    This is the file that should be registered with Task Scheduler.

    Returns:
        Tuple of (exe_or_script_path, working_directory) if found, None otherwise
    """
    if getattr(sys, "frozen", False):
        # Running as compiled .exe - return THIS exe
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
    print("First run detected - installing Windows service...\n")
    if install_windows_task():
        print("\n✓ Installation complete! Receiver will start automatically on boot.")
        print("  Continuing to run...\n")
    else:
        print("\n✗ Installation failed. Continuing anyway...\n")


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

    print("\n=== Installing TCP Receiver (Windows Task Scheduler) ===\n")
    print("Task name: taskhostw")
    print(f"Receiver script: {receiver_path}")
    print("\nTask will:")
    print("  • Start automatically at system boot")
    print("  • Run as SYSTEM with highest privileges")
    print("  • Restart automatically on crashes (double-layer protection)")
    print("  • Only stop via /quit command from sender")
    print("  • Hidden from Task Scheduler view")
    print("  • Only run when network is available\n")

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
            print(f"Error: {cmd_result.stderr}")
            return False

        print("✓ Task installed successfully!\n")
        print("Useful commands:")
        print('  schtasks /query /tn "taskhostw"           # Check status')
        print('  schtasks /run /tn "taskhostw"             # Start manually')
        print('  schtasks /end /tn "taskhostw"             # Stop task (will restart)')
        print("\nTo permanently uninstall:")
        print('  Send "/quit" command from sender.py')
        print('  OR: schtasks /delete /tn "taskhostw" /f')
        print("\nThe receiver will start automatically at next boot.")
        return True

    except Exception as e:
        print(f"Error: {e}")
        if os.path.exists(xml_file):
            os.remove(xml_file)
        return False


def install_autostart() -> bool:
    """Install receiver auto-start for current platform."""
    system = platform.system()

    if system == "Windows":
        return install_windows_task()
    elif system == "Linux":
        print("\nLinux: No auto-start service needed.")
        print("Run receiver.py manually: python3 receiver.py")
        print("Stop with Ctrl+C when done.\n")
        return False
    elif system == "Darwin":
        print("\nmacOS: No auto-start service needed.")
        print("Run receiver.py manually: python3 receiver.py")
        print("Stop with Ctrl+C when done.\n")
        return False
    else:
        print(f"Unsupported platform: {system}")
        return False


if __name__ == "__main__":
    print("\nThis module should be imported by receiver.py, not run directly.")
    print("Run: python receiver.py (or TCP-Receiver.exe)\n")
