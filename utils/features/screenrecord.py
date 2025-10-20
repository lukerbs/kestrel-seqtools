"""
Screen recording feature - Frame streaming architecture
"""

import socket
import threading
import time
from datetime import datetime
from io import BytesIO
from utils.protocol import send_binary, send_text, send_error
from utils.modes import Mode, ModeManager
from utils.config import SCREENRECORD_FPS
from utils.common import log


def start_recording(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Start screen recording - streams frames to sender at 5 FPS.

    Args:
        sock: Socket to stream frames through
        mode_manager: Mode manager instance
    """
    # Check if we can enter recording mode
    if not mode_manager.set_mode(Mode.SCREENRECORD):
        send_error(sock, "Already in another mode. Use /stop first.")
        return

    try:
        import mss
        from PIL import Image
    except ImportError:
        send_error(sock, "Required libraries not available. Install: pip install mss Pillow")
        mode_manager.reset_mode()
        return

    # Get monitor info
    try:
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # Primary monitor
            width = monitor["width"]
            height = monitor["height"]
    except Exception as e:
        send_error(sock, f"Failed to access screen: {e}")
        mode_manager.reset_mode()
        return

    # Generate session timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Send recording start metadata
    metadata = f"{width}x{height}|{SCREENRECORD_FPS}|{timestamp}"
    send_text(sock, f"<RECORDING_START>{metadata}")
    log(f"Screen recording started: {width}x{height} @ {SCREENRECORD_FPS} FPS - session: {timestamp}")

    # Store metadata for stop function
    mode_manager.recording_metadata = {
        "timestamp": timestamp,
        "width": width,
        "height": height,
        "fps": SCREENRECORD_FPS,
    }

    # Start recording in background thread
    def recording_worker():
        """Worker function that captures and streams frames"""
        frame_num = 0
        frame_interval = 1.0 / SCREENRECORD_FPS  # Time between frames

        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1]

                while not mode_manager.is_stopping():
                    start_time = time.time()

                    try:
                        # Capture frame
                        img = sct.grab(monitor)

                        # Convert to PIL Image
                        pil_img = Image.frombytes("RGB", img.size, img.bgra, "raw", "BGRX")

                        # Compress as JPEG
                        buffer = BytesIO()
                        pil_img.save(buffer, format="JPEG", quality=75)
                        frame_data = buffer.getvalue()

                        # Send frame
                        frame_filename = f"frame_{frame_num:06d}"
                        send_binary(sock, frame_filename, frame_data)
                        frame_num += 1

                    except (socket.error, BrokenPipeError, OSError) as e:
                        log(f"Screen recording: Connection error - {e}")
                        break
                    except Exception as e:
                        log(f"Screen recording: Frame capture error - {e}")
                        # Continue trying to capture more frames
                        continue

                    # Maintain frame rate
                    elapsed = time.time() - start_time
                    sleep_time = max(0, frame_interval - elapsed)
                    time.sleep(sleep_time)

        except Exception as e:
            log(f"Screen recording: Fatal error - {e}")
            import traceback

            log(traceback.format_exc())

        log(f"Screen recording thread stopped - {frame_num} frames captured")

    # Start worker thread
    mode_manager.active_thread = threading.Thread(target=recording_worker, daemon=True)
    mode_manager.active_thread.start()


def stop_recording(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Stop screen recording and finalize.

    Args:
        sock: Socket to send confirmation through
        mode_manager: Mode manager instance
    """
    if mode_manager.current_mode != Mode.SCREENRECORD:
        send_error(sock, "Screen recording is not active.")
        return

    # Signal stop
    mode_manager.signal_stop()

    # Wait for thread to finish
    mode_manager.wait_for_thread(timeout=5)

    # Send end marker
    send_text(sock, "<RECORDING_END>")
    log("Screen recording stopped")

    # Reset mode
    mode_manager.reset_mode()
