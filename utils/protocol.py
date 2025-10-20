"""
Network protocol for text and binary data transmission
"""

import struct
import socket
from utils.config import END_MARKER, BINARY_START_MARKER, BUFFER_SIZE


def send_text(sock: socket.socket, message: str) -> None:
    """
    Send a text message with END_MARKER.

    Args:
        sock: Socket to send through
        message: Text message to send
    """
    sock.sendall(message.encode("utf-8"))
    sock.sendall(END_MARKER)


def send_error(sock: socket.socket, message: str) -> None:
    """
    Send an error message with consistent formatting.

    Args:
        sock: Socket to send through
        message: Error message to send
    """
    if not message.startswith("[ERROR"):
        message = f"[ERROR: {message}]"
    if not message.endswith("\n"):
        message += "\n"
    send_text(sock, message)


def receive_text(sock: socket.socket) -> str:
    """
    Receive text data until END_MARKER is encountered.

    Args:
        sock: Socket to receive from

    Returns:
        Decoded text string (without END_MARKER)

    Raises:
        ConnectionError: If connection is lost
    """
    buffer = b""
    while END_MARKER not in buffer:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Connection lost while receiving text")
        buffer += chunk

    # Split on END_MARKER and return only the message part
    return buffer.split(END_MARKER)[0].decode("utf-8")


def send_binary(sock: socket.socket, data_type: str, data: bytes) -> None:
    """
    Send binary data with a header containing type and size.

    Format: <BINARY><TYPE:20s><SIZE:Q><DATA><END_MARKER>

    Args:
        sock: Socket to send through
        data_type: Type identifier (max 20 chars)
        data: Binary data to send
    """
    # Truncate or pad data_type to exactly 20 characters
    type_bytes = data_type.encode("utf-8")[:20].ljust(20, b"\x00")

    # Pack header: type (20 bytes) + size (8-byte unsigned long long)
    # Use ! for network byte order (big-endian) with standard sizes and no padding
    header = struct.pack("!20sQ", type_bytes, len(data))

    # Send: marker + header + data + end marker
    sock.sendall(BINARY_START_MARKER)
    sock.sendall(header)
    sock.sendall(data)
    sock.sendall(END_MARKER)


def receive_binary(sock: socket.socket) -> tuple[str, bytes]:
    """
    Receive binary data with header.

    Returns:
        Tuple of (data_type, binary_data)

    Raises:
        ConnectionError: If connection is lost
        ValueError: If header is malformed
    """
    # Read until we get the BINARY_START_MARKER
    buffer = b""
    while BINARY_START_MARKER not in buffer:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Connection lost while waiting for binary marker")
        buffer += chunk

    # Split off everything before the marker
    buffer = buffer.split(BINARY_START_MARKER, 1)[1]

    # Read header (28 bytes: 20 for type + 8 for size)
    header_size = 28
    while len(buffer) < header_size:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Connection lost while receiving binary header")
        buffer += chunk

    # Parse header
    header = buffer[:header_size]
    buffer = buffer[header_size:]

    try:
        # Use ! for network byte order (big-endian) with standard sizes and no padding
        type_bytes, data_size = struct.unpack("!20sQ", header)
        data_type = type_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
    except (struct.error, UnicodeDecodeError) as e:
        raise ValueError(f"Malformed binary header: {e}")

    # Read data + END_MARKER
    total_size = data_size + len(END_MARKER)
    while len(buffer) < total_size:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Connection lost while receiving binary data")
        buffer += chunk

    # Extract data and verify END_MARKER
    data = buffer[:data_size]
    marker = buffer[data_size : data_size + len(END_MARKER)]

    if marker != END_MARKER:
        raise ValueError("Binary data missing END_MARKER")

    return data_type, data


def peek_for_binary(sock: socket.socket, timeout=0.1) -> bool:
    """
    Check if the next data is binary without consuming it.

    Args:
        sock: Socket to check
        timeout: How long to wait for data (seconds)

    Returns:
        True if next data appears to be binary, False otherwise
    """
    import select

    # Check if data is available
    ready = select.select([sock], [], [], timeout)
    if not ready[0]:
        return False

    # Peek at the data without removing it
    try:
        data = sock.recv(len(BINARY_START_MARKER), socket.MSG_PEEK)
        return data.startswith(BINARY_START_MARKER)
    except (socket.error, OSError):
        return False
