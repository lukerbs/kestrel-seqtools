"""
Input Gatekeeper - Selective blocking of remote desktop input.
Implements a hybrid architecture using Raw Input for device identification
and pynput hooks for enforcement. This version also retains the original
'injected' flag check as a fallback for non-UIAccess injected events.
"""

import queue
import threading
from pynput import keyboard, mouse
from .config import MAX_QUEUE_SIZE, WORKER_TIMEOUT, HYPERVISOR_IDENTIFIERS, TOGGLE_HOTKEY
from . import win32_raw_input


class InputGatekeeper:
    """
    Selectively blocks non-whitelisted and injected input while allowing
    whitelisted (host) input.
    """

    def __init__(self, log_func=None):
        """
        Initialize the Input Gatekeeper.

        Args:
            log_func: Optional logging function (for dev mode)
        """
        self._log = log_func if log_func else lambda msg: None

        # Controllers for re-emitting host input
        self._mouse_controller = mouse.Controller()
        self._keyboard_controller = keyboard.Controller()

        # Queues for the suppress-and-re-emit pattern
        self._mouse_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._keyboard_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)

        # Queue for decisions from the Raw Input thread
        self._decision_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)

        # Threads and control flags
        self._stop_event = threading.Event()
        self._active = False
        self._raw_input_thread = None
        self._kbd_listener = None
        self._mouse_listener = None
        self._kbd_worker = None
        self._mouse_worker = None

        # Whitelist for hypervisor device handles
        self._device_whitelist = set()

        # Track currently pressed keys for hotkey detection
        self._pressed_keys = set()

        # Flags to prevent feedback loops (when workers re-emit, ignore those events)
        # Using separate flags for keyboard/mouse to avoid cross-blocking
        self._emitting_lock = threading.Lock()
        self._emitting_keyboard = False
        self._emitting_mouse = False

        # Statistics
        self.stats = {
            "blocked_keys": 0,
            "blocked_clicks": 0,
            "blocked_moves": 0,
            "allowed_keys": 0,
            "allowed_clicks": 0,
            "dropped_events": 0,
        }

    # ========================================================================
    # HOTKEY WHITELIST HELPERS
    # ========================================================================

    def _normalize_key(self, key):
        """
        Normalize a key for comparison.
        - Character keys (with .char attribute) → lowercase string
        - Special keys (Key.shift, Key.cmd_l, etc.) → the Key object itself
        """
        try:
            if hasattr(key, "char") and key.char is not None:
                return key.char.lower()
            else:
                # Special key (Key.shift, Key.cmd_l, etc.)
                return key
        except AttributeError:
            return key

    def _is_hotkey_pressed(self):
        """
        Check if the toggle hotkey combination is currently pressed.
        TOGGLE_HOTKEY is a set like {Key.cmd_l, Key.shift, "f"}
        We need to normalize it the same way we normalize pressed keys.
        """
        normalized_hotkey = set()
        for key in TOGGLE_HOTKEY:
            if isinstance(key, str):
                # String keys (like "f") should be lowercase
                normalized_hotkey.add(key.lower())
            else:
                # Key objects (like Key.shift) stay as-is
                normalized_hotkey.add(key)

        # Check if all hotkey keys are currently pressed
        return normalized_hotkey.issubset(self._pressed_keys)

    # ========================================================================
    # LISTENER CALLBACKS (Time-Critical - Must be Fast!)
    # ========================================================================

    def _get_decision(self, injected):
        """
        Gets a decision from the Raw Input thread or the injected flag.

        PRIORITY ORDER (most reliable first):
        1. Raw Input device handle (most reliable - hardware-level)
        2. Injected flag (fallback - can have false positives with VMs)
        3. Default ALLOW (safety - prevents lockout on race conditions)

        Args:
            injected: Boolean flag from pynput indicating if event was programmatically injected

        Returns:
            str: Decision string - "ALLOW", "DENY", or "DENY_INJECTED"
        """
        # FIRST CHECK: Raw Input queue (most reliable - checks actual device handle)
        try:
            decision = self._decision_queue.get_nowait()
            # If Raw Input says ALLOW, trust it even if injected flag is True
            # (This handles VMs that inject input but use whitelisted devices)
            self._log(f"[DEBUG] Raw Input decision from queue: {decision}")
            return decision
        except queue.Empty:
            self._log(f"[DEBUG] Raw Input queue empty, checking injected flag")
            pass  # Queue empty, fall through to next check

        # SECOND CHECK: Injected flag (fallback for events without Raw Input data)
        if injected:
            # Only block if Raw Input didn't explicitly allow it
            self._log(f"[DEBUG] Event marked as injected, returning DENY_INJECTED")
            return "DENY_INJECTED"

        # THIRD CHECK: Default ALLOW (safety - prevents lockout)
        # This handles race conditions where pynput hook fires before Raw Input thread
        self._log(f"[DEBUG] No queue data and not injected, defaulting to ALLOW")
        return "ALLOW"

    def _on_press(self, key, injected):
        """Keyboard press callback - runs on OS input thread"""
        # FIRST CHECK: Ignore our own re-emitted keyboard events (prevents feedback loop)
        with self._emitting_lock:
            if self._emitting_keyboard:
                return  # Silently ignore - this is our own re-emitted event

        key_repr = f"'{key.char}'" if hasattr(key, "char") else str(key)

        # DEBUG: Log every key press with injected flag
        self._log(f"[DEBUG] _on_press fired: key={key_repr}, injected={injected}")

        # Track pressed keys for hotkey detection
        normalized_key = self._normalize_key(key)
        self._pressed_keys.add(normalized_key)

        # ALWAYS allow the toggle hotkey combination, regardless of source
        if self._is_hotkey_pressed():
            self._log(f"[DEBUG] Hotkey detected, allowing {key_repr}")
            try:
                self._keyboard_queue.put_nowait(("press", key))
                self.stats["allowed_keys"] += 1
                self._log(f"[DEBUG] Added {key_repr} to re-emit queue (hotkey)")
            except queue.Full:
                self.stats["dropped_events"] += 1
                self._log("[GATEKEEPER] Keyboard queue full, dropped event")
            return

        # For all other keys, check device/injected status
        decision = self._get_decision(injected)
        self._log(f"[DEBUG] Decision for {key_repr}: {decision}")

        if decision == "ALLOW":
            try:
                self._keyboard_queue.put_nowait(("press", key))
                self.stats["allowed_keys"] += 1
                self._log(f"[DEBUG] Added {key_repr} to re-emit queue (allowed)")
            except queue.Full:
                self.stats["dropped_events"] += 1
                self._log("[GATEKEEPER] Keyboard queue full, dropped event")
        else:  # DENY_INJECTED or DENY
            self.stats["blocked_keys"] += 1
            self._log(f"[BLOCKED] Remote key press: {key_repr} (Reason: {decision})")

    def _on_release(self, key, injected):
        """Keyboard release callback"""
        # FIRST CHECK: Ignore our own re-emitted keyboard events (prevents feedback loop)
        with self._emitting_lock:
            if self._emitting_keyboard:
                return  # Silently ignore - this is our own re-emitted event

        # Check if hotkey is currently pressed BEFORE removing this key
        hotkey_was_pressed = self._is_hotkey_pressed()

        # Remove key from pressed set
        normalized_key = self._normalize_key(key)
        self._pressed_keys.discard(normalized_key)

        # ALWAYS allow release if the hotkey combo was active when this key was released
        # This ensures the complete hotkey sequence (press AND release) goes through
        if hotkey_was_pressed:
            try:
                self._keyboard_queue.put_nowait(("release", key))
            except queue.Full:
                self.stats["dropped_events"] += 1
            return

        # For all other keys, check device/injected status
        decision = self._get_decision(injected)

        if decision == "ALLOW":
            try:
                self._keyboard_queue.put_nowait(("release", key))
            except queue.Full:
                self.stats["dropped_events"] += 1
        # No logging for denied release events to reduce noise

    def _on_click(self, x, y, button, pressed, injected):
        """Mouse click callback"""
        # FIRST CHECK: Ignore our own re-emitted mouse events (prevents feedback loop)
        with self._emitting_lock:
            if self._emitting_mouse:
                return  # Silently ignore - this is our own re-emitted event

        action = "pressed" if pressed else "released"

        # DEBUG: Log every mouse click with injected flag
        self._log(f"[DEBUG] _on_click fired: button={button} {action} at ({x},{y}), injected={injected}")

        decision = self._get_decision(injected)
        self._log(f"[DEBUG] Decision for mouse {action}: {decision}")

        if decision == "ALLOW":
            try:
                self._mouse_queue.put_nowait(("click", (x, y, button, pressed)))
                if pressed:
                    self.stats["allowed_clicks"] += 1
                self._log(f"[DEBUG] Added mouse {action} to re-emit queue (allowed)")
            except queue.Full:
                self.stats["dropped_events"] += 1
        else:  # DENY
            if pressed:
                self.stats["blocked_clicks"] += 1
            self._log(f"[BLOCKED] Remote mouse {action}: {button} at ({x}, {y}) (Reason: {decision})")

    def _on_move(self, x, y, injected):
        """Mouse move callback"""
        # FIRST CHECK: Ignore our own re-emitted mouse events (prevents feedback loop)
        with self._emitting_lock:
            if self._emitting_mouse:
                return  # Silently ignore - this is our own re-emitted event

        decision = self._get_decision(injected)

        if decision == "ALLOW":
            try:
                self._mouse_queue.put_nowait(("move", (x, y)))
            except queue.Full:
                self.stats["dropped_events"] += 1
        else:  # DENY
            self.stats["blocked_moves"] += 1
            # Don't log moves - too noisy

    def _on_scroll(self, x, y, dx, dy, injected):
        """Mouse scroll callback"""
        # FIRST CHECK: Ignore our own re-emitted mouse events (prevents feedback loop)
        with self._emitting_lock:
            if self._emitting_mouse:
                return  # Silently ignore - this is our own re-emitted event

        decision = self._get_decision(injected)

        if decision == "ALLOW":
            try:
                self._mouse_queue.put_nowait(("scroll", (x, y, dx, dy)))
            except queue.Full:
                self.stats["dropped_events"] += 1
        # No logging for denied scroll events

    # ========================================================================
    # WORKER THREADS (Non-Time-Critical - Re-emit Events)
    # ========================================================================

    def _keyboard_worker(self):
        """Worker thread to re-emit keyboard events from host"""
        while not self._stop_event.is_set():
            try:
                event_type, key = self._keyboard_queue.get(timeout=WORKER_TIMEOUT)
                key_repr = f"'{key.char}'" if hasattr(key, "char") else str(key)

                # DEBUG: Log before re-emitting
                self._log(f"[DEBUG] Worker re-emitting: {event_type} {key_repr}")

                # Set flag to prevent feedback loop
                with self._emitting_lock:
                    self._emitting_keyboard = True

                try:
                    if event_type == "press":
                        self._keyboard_controller.press(key)
                    elif event_type == "release":
                        self._keyboard_controller.release(key)
                finally:
                    # Always clear flag, even if exception occurs
                    with self._emitting_lock:
                        self._emitting_keyboard = False

                # DEBUG: Log after re-emitting
                self._log(f"[DEBUG] Worker completed re-emit: {event_type} {key_repr}")
            except queue.Empty:
                continue
            except Exception as e:
                self._log(f"[ERROR] Keyboard worker error: {e}")
                # Ensure flag is cleared on error
                with self._emitting_lock:
                    self._emitting_keyboard = False

    def _mouse_worker(self):
        """Worker thread to re-emit mouse events from host"""
        while not self._stop_event.is_set():
            try:
                event_type, args = self._mouse_queue.get(timeout=WORKER_TIMEOUT)

                # DEBUG: Log before re-emitting
                if event_type == "click":
                    x, y, button, pressed = args
                    action = "press" if pressed else "release"
                    self._log(f"[DEBUG] Worker re-emitting: mouse {action} {button} at ({x},{y})")
                elif event_type == "move":
                    self._log(f"[DEBUG] Worker re-emitting: mouse move to {args}")
                elif event_type == "scroll":
                    self._log(f"[DEBUG] Worker re-emitting: mouse scroll")

                # Set flag to prevent feedback loop
                with self._emitting_lock:
                    self._emitting_mouse = True

                try:
                    if event_type == "move":
                        self._mouse_controller.position = args
                    elif event_type == "click":
                        x, y, button, pressed = args
                        self._mouse_controller.position = (x, y)
                        if pressed:
                            self._mouse_controller.press(button)
                        else:
                            self._mouse_controller.release(button)
                    elif event_type == "scroll":
                        x, y, dx, dy = args
                        self._mouse_controller.position = (x, y)
                        self._mouse_controller.scroll(dx, dy)
                finally:
                    # Always clear flag, even if exception occurs
                    with self._emitting_lock:
                        self._emitting_mouse = False

                # DEBUG: Log after re-emitting
                self._log(f"[DEBUG] Worker completed re-emit: {event_type}")
            except queue.Empty:
                continue
            except Exception as e:
                self._log(f"[ERROR] Mouse worker error: {e}")
                # Ensure flag is cleared on error
                with self._emitting_lock:
                    self._emitting_mouse = False

    # ========================================================================
    # PUBLIC METHODS
    # ========================================================================

    def start(self):
        """Activate selective input blocking"""
        if self._active:
            self._log("[GATEKEEPER] Already active")
            return

        self._log("[GATEKEEPER] Starting input firewall...")

        # 1. Build device whitelist using Raw Input API
        self._device_whitelist = win32_raw_input.build_device_whitelist(HYPERVISOR_IDENTIFIERS, self._log)

        # FAIL-SAFE: If no devices found, abort activation to prevent locking out the user
        if not self._device_whitelist:
            self._log("[GATEKEEPER] CRITICAL: No whitelisted devices found!")
            self._log("[GATEKEEPER] FAIL-SAFE: Refusing to activate firewall to prevent lockout")
            self._log("[GATEKEEPER] Please check HYPERVISOR_IDENTIFIERS in config.py")
            self._log("[GATEKEEPER] Run debug_devices.ps1 to see available devices")
            return  # Abort activation

        self._log(f"[GATEKEEPER] Whitelisted {len(self._device_whitelist)} device(s)")
        self._active = True
        self._stop_event.clear()

        # Clear any stale key state from previous session
        self._pressed_keys.clear()

        # 2. Start Raw Input identification thread
        self._raw_input_thread = win32_raw_input.RawInputThread(self._device_whitelist, self._decision_queue, self._log)
        self._raw_input_thread.start()

        # 3. Start pynput listeners with suppress=True for enforcement
        self._kbd_listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release, suppress=True)
        self._mouse_listener = mouse.Listener(
            on_click=self._on_click, on_move=self._on_move, on_scroll=self._on_scroll, suppress=True
        )

        # 4. Start worker threads for re-emitting allowed events
        self._kbd_worker = threading.Thread(target=self._keyboard_worker, daemon=True, name="KeyboardWorker")
        self._mouse_worker = threading.Thread(target=self._mouse_worker, daemon=True, name="MouseWorker")

        self._kbd_worker.start()
        self._mouse_worker.start()
        self._kbd_listener.start()
        self._mouse_listener.start()

        self._log("[GATEKEEPER] Input firewall ACTIVE - blocking remote input")

    def stop(self):
        """Deactivate and restore all input"""
        if not self._active:
            return

        self._log("[GATEKEEPER] Stopping input firewall...")
        self._active = False
        self._stop_event.set()

        # Stop Raw Input thread
        if self._raw_input_thread:
            self._raw_input_thread.stop()

        # Stop pynput listeners
        if self._kbd_listener:
            self._kbd_listener.stop()
        if self._mouse_listener:
            self._mouse_listener.stop()

        # Wait for threads to finish
        if self._raw_input_thread:
            self._raw_input_thread.join(timeout=2)
        if self._kbd_worker:
            self._kbd_worker.join(timeout=2)
        if self._mouse_worker:
            self._mouse_worker.join(timeout=2)

        # Clear pressed keys tracking
        self._pressed_keys.clear()

        self._log("[GATEKEEPER] Input firewall INACTIVE - all input restored")

    def is_active(self):
        """Check if firewall is currently active"""
        return self._active

    def get_stats(self):
        """Get statistics about blocked/allowed events"""
        return self.stats.copy()
