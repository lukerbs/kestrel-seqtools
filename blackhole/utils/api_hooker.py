"""
API Hooker - Uses Frida to hook SendInput() in target processes
"""

import frida
import sys

from .config import MAGIC_TAG


# Frida JavaScript payload to inject into target process
# This hooks user32.dll!SendInput and tags all INPUT structures with our magic value
FRIDA_SCRIPT = f"""
// Get SendInput function from user32.dll
var sendInput = Module.findExportByName('user32.dll', 'SendInput');

if (!sendInput) {{
    send({{type: 'error', message: 'SendInput not found in user32.dll'}});
}} else {{
    // Determine INPUT structure size based on architecture
    var inputSize = Process.pointerSize === 8 ? 40 : 28;  // 64-bit: 40 bytes, 32-bit: 28 bytes
    
    // Hook SendInput
    Interceptor.attach(sendInput, {{
        onEnter: function(args) {{
            try {{
                // args[0] = cInputs (number of INPUT structures)
                // args[1] = pInputs (pointer to INPUT array)
                // args[2] = cbSize (size of INPUT structure)
                
                var count = args[0].toInt32();
                var pInputs = args[1];  // args[1] is already a NativePointer
                
                if (count > 0 && pInputs && !pInputs.isNull()) {{
                    // Iterate through INPUT structures and tag them
                    for (var i = 0; i < count; i++) {{
                        var pInput = pInputs.add(i * inputSize);
                        var type = pInput.readU32();  // INPUT.type (first 4 bytes)
                        
                        if (type === 1) {{  // INPUT_KEYBOARD
                            // Offset to ki.dwExtraInfo
                            // 64-bit: 4 (type) + 4 (pad) + 12 (ki fields) = 20
                            // 32-bit: 4 (type) + 12 (ki fields) = 16
                            var extraInfoOffset = Process.pointerSize === 8 ? 20 : 16;
                            // Use writePointer to automatically write 32 or 64 bits
                            pInput.add(extraInfoOffset).writePointer(ptr('{MAGIC_TAG:#x}'));
                        }}
                        else if (type === 0) {{  // INPUT_MOUSE
                            // Offset to mi.dwExtraInfo
                            // 64-bit: 4 (type) + 4 (pad) + 20 (mi fields) = 28
                            // 32-bit: 4 (type) + 20 (mi fields) = 24
                            var extraInfoOffset = Process.pointerSize === 8 ? 28 : 24;
                            // Use writePointer to automatically write 32 or 64 bits
                            pInput.add(extraInfoOffset).writePointer(ptr('{MAGIC_TAG:#x}'));
                        }}
                    }}
                    
                    // Notify that we tagged events (only in verbose mode)
                    // send({{type: 'tagged', count: count}});
                }}
            }} catch (e) {{
                send({{type: 'error', message: 'Error in onEnter: ' + e.message}});
            }}
        }}
    }});
    
    send({{type: 'ready'}});
}}
"""


class APIHooker:
    """
    Manages Frida-based API hooks on target remote desktop processes.
    Hooks user32.dll!SendInput to tag input with MAGIC_TAG.
    """

    def __init__(self, log_func=None):
        """
        Initialize the API hooker.

        Args:
            log_func: Optional logging function
        """
        self._log = log_func if log_func else lambda msg: None
        self._sessions = {}  # {pid: frida.Session}
        self._scripts = {}  # {pid: frida.Script}

    def hook_process(self, pid, process_name):
        """
        Hook SendInput() in the target process.

        Args:
            pid: Process ID to hook
            process_name: Name of the process (for logging)

        Returns:
            bool: True if successful, False otherwise
        """
        if pid in self._sessions:
            self._log(f"[HOOKER] Already hooked: {process_name} (PID: {pid})")
            return True

        try:
            self._log(f"[HOOKER] Attaching to {process_name} (PID: {pid})...")

            # Attach to the process
            session = frida.attach(pid)

            # Create and load the Frida script
            script = session.create_script(FRIDA_SCRIPT)
            script.on("message", lambda msg, data: self._on_message(pid, process_name, msg, data))
            script.load()

            # Store session and script
            self._sessions[pid] = session
            self._scripts[pid] = script

            self._log(f"[HOOKER] Successfully hooked {process_name} (PID: {pid})")
            return True

        except frida.ProcessNotFoundError:
            self._log(f"[HOOKER] ERROR: Process {pid} not found")
            return False

        except frida.PermissionDeniedError:
            self._log(f"[HOOKER] ERROR: Permission denied for PID {pid}")
            self._log(f"[HOOKER] NOTE: Frida requires administrator privileges")
            return False

        except Exception as e:
            self._log(f"[HOOKER] ERROR: Failed to hook PID {pid}: {e}")
            return False

    def unhook_process(self, pid):
        """
        Remove hook from process.

        Args:
            pid: Process ID to unhook
        """
        if pid not in self._sessions:
            return

        try:
            # Unload script and detach session
            if pid in self._scripts:
                self._scripts[pid].unload()
                del self._scripts[pid]

            if pid in self._sessions:
                self._sessions[pid].detach()
                del self._sessions[pid]

            self._log(f"[HOOKER] Unhooked PID {pid}")

        except Exception as e:
            self._log(f"[HOOKER] Error unhooking PID {pid}: {e}")

    def unhook_all(self):
        """Remove all hooks"""
        self._log("[HOOKER] Unhooking all processes...")
        for pid in list(self._sessions.keys()):
            self.unhook_process(pid)

    def get_hooked_processes(self):
        """
        Get list of currently hooked process IDs.

        Returns:
            list: List of PIDs
        """
        return list(self._sessions.keys())

    def _on_message(self, pid, process_name, message, data):
        """
        Handle messages from Frida script.

        Args:
            pid: Process ID
            process_name: Process name
            message: Message from Frida
            data: Additional data
        """
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "ready":
                self._log(f"[HOOKER] Hook active in {process_name} (PID: {pid})")

            elif msg_type == "tagged":
                # Only log in verbose mode (too spammy otherwise)
                count = payload.get("count", 0)
                # self._log(f"[HOOKER] Tagged {count} input(s) from {process_name}")

            elif msg_type == "error":
                error_msg = payload.get("message", "Unknown error")
                self._log(f"[HOOKER] Frida error in {process_name} (PID: {pid}): {error_msg}")

        elif message["type"] == "error":
            # Frida internal error
            self._log(f"[HOOKER] Frida internal error in PID {pid}: {message}")
