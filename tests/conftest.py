"""
Pytest configuration and fixtures for Kestrel Seqtools tests
"""

import pytest
import socket
from unittest.mock import Mock, MagicMock
from utils.modes import ModeManager


@pytest.fixture
def mock_socket():
    """Create a mock socket object"""
    sock = Mock(spec=socket.socket)
    sock.sendall = Mock()
    sock.recv = Mock()
    sock.close = Mock()
    return sock


@pytest.fixture
def mode_manager():
    """Create a fresh ModeManager instance"""
    return ModeManager()


@pytest.fixture
def mock_connection():
    """Create a mock connection (socket + address)"""
    sock = Mock(spec=socket.socket)
    address = ("127.0.0.1", 12345)
    return sock, address


@pytest.fixture
def data_directory(tmp_path):
    """Create temporary data directories for testing"""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    
    (data_dir / "keylogs").mkdir()
    (data_dir / "screenshots").mkdir()
    (data_dir / "snapshots").mkdir()
    (data_dir / "screenrecordings").mkdir()
    
    return data_dir

