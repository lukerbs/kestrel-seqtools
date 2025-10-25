"""
Screenshot feature - Capture screen using mss
"""

import socket
from datetime import datetime
from utils.protocol import send_binary, send_error
from utils.modes import ModeManager
from utils.common import log


def take_screenshot(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Capture a screenshot of the primary monitor and send to sender.

    Args:
        sock: Socket to send screenshot through
        mode_manager: Mode manager instance (not used but kept for consistency)
    """
    try:
        import mss
        import mss.tools

        log("Taking screenshot...")

        # Capture primary monitor
        with mss.mss() as sct:
            # Monitor 1 is the primary monitor (monitor 0 is all monitors combined)
            monitor = sct.monitors[1]
            screenshot = sct.grab(monitor)

            # Convert to PNG bytes
            png_data = mss.tools.to_png(screenshot.rgb, screenshot.size)

            # Generate filename with timestamp (compact format to fit 20-char protocol limit)
            timestamp = datetime.now().strftime("%m%d%H%M%S")  # MMDDHHMISS = 10 chars
            filename = f"ss_{timestamp}.png"  # ss_ (3) + timestamp (10) + .png (4) = 17 chars

            # Send binary data
            send_binary(sock, filename, png_data, mode_manager.socket_write_lock)
            log(f"Screenshot sent: {filename} ({len(png_data)} bytes)")

    except ImportError:
        send_error(sock, "mss library not available. Install with: pip install mss", mode_manager.socket_write_lock)
        log("Screenshot failed: mss not installed")

    except Exception as e:
        send_error(sock, f"Screenshot failed: {e}", mode_manager.socket_write_lock)
        log(f"Screenshot error: {e}")
