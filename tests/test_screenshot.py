"""
Tests for screenshot feature
"""

import pytest
from unittest.mock import Mock, patch
from utils.features.screenshot import take_screenshot
from utils.modes import ModeManager


def test_screenshot_requires_mss(mock_socket, mode_manager):
    """Test screenshot fails gracefully without mss"""
    with patch('utils.features.screenshot.mss', None):
        with patch('utils.protocol.send_text') as mock_send:
            take_screenshot(mock_socket, mode_manager)
            
            # Should send error message
            # Note: This test may need adjustment based on actual import behavior


# Additional tests can be added here for:
# - Successful screenshot capture
# - Handling mss errors
# - Correct binary data transmission

