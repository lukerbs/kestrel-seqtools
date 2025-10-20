"""
Tests for network protocol (send_text, send_binary, receive_text, receive_binary)
"""

import pytest
from unittest.mock import Mock, call
from utils.protocol import send_text, send_binary
from utils.config import END_MARKER, BINARY_START_MARKER


def test_send_text(mock_socket):
    """Test sending text message"""
    send_text(mock_socket, "Hello, World!")
    
    # Verify sendall was called twice (message + end marker)
    assert mock_socket.sendall.call_count == 2
    assert mock_socket.sendall.call_args_list[0] == call(b"Hello, World!")
    assert mock_socket.sendall.call_args_list[1] == call(END_MARKER)


def test_send_binary(mock_socket):
    """Test sending binary data"""
    data = b"\x00\x01\x02\x03\x04"
    send_binary(mock_socket, "testfile.bin", data)
    
    # Verify sendall was called 4 times (marker + header + data + end marker)
    assert mock_socket.sendall.call_count == 4
    assert mock_socket.sendall.call_args_list[0] == call(BINARY_START_MARKER)
    # Header contains type (20 bytes) + size (8 bytes)
    assert mock_socket.sendall.call_args_list[3] == call(END_MARKER)


def test_send_binary_long_type(mock_socket):
    """Test sending binary with type name > 20 chars (should truncate)"""
    data = b"test"
    long_type = "a" * 30  # 30 characters
    send_binary(mock_socket, long_type, data)
    
    # Should not raise error and should truncate type name
    assert mock_socket.sendall.call_count == 4

