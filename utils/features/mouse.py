"""
Mouse jitter feature - Erratic mouse movements
"""

import socket
import threading
import time
import random
from utils.protocol import send_text, send_error
from utils.modes import Mode, ModeManager
from utils.common import log


def start_jitter(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Start mouse jitter mode - large erratic movements (±100px every 100ms).

    Args:
        sock: Socket to send confirmation through
        mode_manager: Mode manager instance
    """
    # Check if we can enter jitter mode
    if not mode_manager.set_mode(Mode.MOUSE_JITTER):
        send_error(sock, "Already in another mode. Use /stop first.", mode_manager.socket_write_lock)
        return

    try:
        from pynput.mouse import Controller
    except ImportError:
        send_error(
            sock, "pynput library not available. Install with: pip install pynput", mode_manager.socket_write_lock
        )
        mode_manager.reset_mode()
        return

    # Send confirmation
    send_text(sock, "[Mouse jitter started. Use /stop to end.]\n", mode_manager.socket_write_lock)
    log("Mouse jitter started")

    # Start jitter in background thread
    def jitter_worker():
        """Worker function that moves the mouse erratically"""
        mouse = Controller()

        try:
            while not mode_manager.is_stopping():
                # Large random movements
                dx = random.randint(-100, 100)
                dy = random.randint(-100, 100)

                try:
                    mouse.move(dx, dy)
                except Exception as e:
                    log(f"Mouse jitter error: {e}")
                    break

                # 100ms delay = 10 jitters per second
                time.sleep(0.1)

        except Exception as e:
            log(f"Mouse jitter worker error: {e}")

        log("Mouse jitter thread stopped")

    # Start worker thread
    mode_manager.active_thread = threading.Thread(target=jitter_worker, daemon=True)
    mode_manager.active_thread.start()


def stop_jitter(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Stop mouse jitter mode.

    Args:
        sock: Socket to send confirmation through
        mode_manager: Mode manager instance
    """
    if mode_manager.current_mode != Mode.MOUSE_JITTER:
        send_error(sock, "Mouse jitter is not running.", mode_manager.socket_write_lock)
        return

    # Signal stop
    mode_manager.signal_stop()

    # Wait for thread to finish
    mode_manager.wait_for_thread(timeout=2)

    # Send confirmation
    send_text(sock, "[Mouse jitter stopped.]\n", mode_manager.socket_write_lock)
    log("Mouse jitter stopped")

    # Reset mode
    mode_manager.reset_mode()
