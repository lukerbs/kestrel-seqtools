"""
Tests for CommandRouter
"""

import pytest
from unittest.mock import Mock, patch
from utils.router import CommandRouter
from utils.modes import Mode, ModeManager


def test_router_initialization(mode_manager):
    """Test router initializes with handlers"""
    router = CommandRouter(mode_manager)
    
    assert router.mode_manager is mode_manager
    assert len(router.handlers) > 0
    assert "/help" in router.handlers
    assert "/screenshot" in router.handlers
    assert "/quit" in router.handlers


def test_router_help_command(mock_socket, mode_manager):
    """Test /help command"""
    router = CommandRouter(mode_manager)
    
    with patch('utils.protocol.send_text') as mock_send:
        router.handle_command("/help", mock_socket)
        
        # Verify send_text was called with help message
        assert mock_send.called
        args = mock_send.call_args[0]
        assert "Available commands" in args[1]


def test_router_normal_mode_shell_command(mock_socket, mode_manager):
    """Test shell command execution in NORMAL mode"""
    router = CommandRouter(mode_manager)
    
    with patch('utils.features.shell.execute_command_stream') as mock_exec:
        mock_exec.return_value = "/home/user"
        router.handle_command("ls -la", mock_socket)
        
        # Verify execute_command_stream was called
        assert mock_exec.called
        assert mock_exec.call_args[0][0] == "ls -la"


def test_router_blocks_commands_in_other_mode(mock_socket, mode_manager):
    """Test that shell commands are blocked when in another mode"""
    router = CommandRouter(mode_manager)
    mode_manager.set_mode(Mode.KEYLOGGER)
    
    with patch('utils.protocol.send_text') as mock_send:
        router.handle_command("ls -la", mock_socket)
        
        # Verify warning was sent
        assert mock_send.called
        args = mock_send.call_args[0]
        assert "WARNING" in args[1]
        assert "keylogger" in args[1].lower()

