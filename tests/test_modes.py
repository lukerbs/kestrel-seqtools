"""
Tests for Mode and ModeManager
"""

import pytest
from utils.modes import Mode, ModeManager


def test_mode_enum():
    """Test Mode enum values"""
    assert Mode.NORMAL.value == "normal"
    assert Mode.KEYLOGGER.value == "keylogger"
    assert Mode.SCREENRECORD.value == "screenrecord"
    assert Mode.MOUSE_JITTER.value == "mouse_jitter"
    assert Mode.BLACKHOLE.value == "blackhole"


def test_mode_manager_initialization():
    """Test ModeManager initializes in NORMAL mode"""
    manager = ModeManager()
    assert manager.current_mode == Mode.NORMAL
    assert manager.active_thread is None
    assert not manager.is_stopping()


def test_mode_manager_set_mode_success():
    """Test setting mode when in NORMAL"""
    manager = ModeManager()
    
    result = manager.set_mode(Mode.KEYLOGGER)
    assert result is True
    assert manager.current_mode == Mode.KEYLOGGER


def test_mode_manager_set_mode_failure():
    """Test setting mode when already in another mode"""
    manager = ModeManager()
    manager.set_mode(Mode.KEYLOGGER)
    
    result = manager.set_mode(Mode.SCREENRECORD)
    assert result is False
    assert manager.current_mode == Mode.KEYLOGGER  # Should not change


def test_mode_manager_reset():
    """Test resetting to NORMAL mode"""
    manager = ModeManager()
    manager.set_mode(Mode.MOUSE_JITTER)
    
    manager.reset_mode()
    assert manager.current_mode == Mode.NORMAL
    assert not manager.is_stopping()


def test_mode_manager_stop_signal():
    """Test stop signal functionality"""
    manager = ModeManager()
    
    assert not manager.is_stopping()
    manager.signal_stop()
    assert manager.is_stopping()
    
    manager.reset_mode()
    assert not manager.is_stopping()

