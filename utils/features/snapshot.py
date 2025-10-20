"""
Webcam snapshot feature - Capture webcam using OpenCV
"""

import socket
from datetime import datetime
from utils.protocol import send_binary, send_error
from utils.modes import ModeManager
from utils.common import log


def take_webcam_snapshot(sock: socket.socket, mode_manager: ModeManager) -> None:
    """
    Capture a single frame from the webcam and send to sender.

    Args:
        sock: Socket to send snapshot through
        mode_manager: Mode manager instance (not used but kept for consistency)
    """
    try:
        import cv2

        log("Capturing webcam snapshot...")

        # Open webcam (device 0)
        cap = cv2.VideoCapture(0)

        if not cap.isOpened():
            send_error(sock, "No webcam detected or webcam is in use.")
            log("Webcam snapshot failed: No webcam available")
            return

        # Capture a single frame
        ret, frame = cap.read()
        cap.release()

        if not ret or frame is None:
            send_error(sock, "Failed to capture webcam frame.")
            log("Webcam snapshot failed: Could not capture frame")
            return

        # Encode frame as JPEG
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 85]
        ret, jpeg_data = cv2.imencode(".jpg", frame, encode_param)

        if not ret:
            send_error(sock, "Failed to encode webcam image.")
            log("Webcam snapshot failed: Encoding error")
            return

        # Convert to bytes
        jpeg_bytes = jpeg_data.tobytes()

        # Generate filename with timestamp (compact format to fit 20-char protocol limit)
        timestamp = datetime.now().strftime("%m%d%H%M%S")  # MMDDHHMISS = 10 chars
        filename = f"snap_{timestamp}.jpg"  # snap_ (5) + timestamp (10) + .jpg (4) = 19 chars

        # Send binary data
        send_binary(sock, filename, jpeg_bytes)
        log(f"Webcam snapshot sent: {filename} ({len(jpeg_bytes)} bytes)")

    except ImportError:
        send_error(sock, "opencv-python library not available. Install with: pip install opencv-python")
        log("Webcam snapshot failed: opencv-python not installed")

    except Exception as e:
        send_error(sock, f"Webcam snapshot failed: {e}")
        log(f"Webcam snapshot error: {e}")
