"""
Input Gatekeeper - Selective blocking of remote desktop input.
Implements a hybrid architecture using Raw Input for device identification
and pynput hooks for enforcement. This version also retains the original
'injected' flag check as a fallback for non-UIAccess injected events.
"""

import queue
import threading
from pynput import keyboard, mouse
from .config import MAX_QUEUE_SIZE, WORKER_TIMEOUT, HYPERVISOR_IDENTIFIERS
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
    # LISTENER CALLBACKS (Time-Critical - Must be Fast!)
    # ========================================================================

    def _get_decision(self, injected):
        """
        Gets a decision from the Raw Input thread or the injected flag.
        - If 'injected' is True, it's a simple injected event. DENY.
        - Otherwise, check the Raw Input queue.
        - If queue has a decision, use it.
        - If queue is empty, it could be a UIAccess event OR a legitimate
          host event that the pynput hook saw before the Raw Input thread.
          To prevent blocking the user, we default to ALLOW in this case.

        Args:
            injected: Boolean flag from pynput indicating if event was programmatically injected

        Returns:
            str: Decision string - "ALLOW", "DENY_INJECTED", or "DENY"
        """
        # First check: simple injected flag (catches non-UIAccess tools)
        if injected:
            return "DENY_INJECTED"

        # Second check: Raw Input queue (catches UIAccess tools by device handle)
        try:
            # Check if the Raw Input thread has already made a decision
            return self._decision_queue.get_nowait()
        except queue.Empty:
            # The queue is empty. This can mean two things:
            # 1. It's a UIAccess event that doesn't generate Raw Input.
            # 2. It's a legitimate host event, but this hook thread won the
            #    race against the Raw Input thread.
            #
            # To prioritize usability and never block the host, we choose
            # to ALLOW the event. The risk of a UIAccess event slipping
            # through in this tiny time window is negligible.
            return "ALLOW"

    def _on_press(self, key, injected):
        """Keyboard press callback - runs on OS input thread"""
        decision = self._get_decision(injected)

        if decision == "ALLOW":
            try:
                self._keyboard_queue.put_nowait(("press", key))
                self.stats["allowed_keys"] += 1
            except queue.Full:
                self.stats["dropped_events"] += 1
                self._log("[GATEKEEPER] Keyboard queue full, dropped event")
        else:  # DENY_INJECTED or DENY
            self.stats["blocked_keys"] += 1
            key_repr = f"'{key.char}'" if hasattr(key, "char") else str(key)
            self._log(f"[BLOCKED] Remote key press: {key_repr} (Reason: {decision})")

    def _on_release(self, key, injected):
        """Keyboard release callback"""
        decision = self._get_decision(injected)

        if decision == "ALLOW":
            try:
                self._keyboard_queue.put_nowait(("release", key))
            except queue.Full:
                self.stats["dropped_events"] += 1
        # No logging for denied release events to reduce noise

    def _on_click(self, x, y, button, pressed, injected):
        """Mouse click callback"""
        decision = self._get_decision(injected)

        if decision == "ALLOW":
            try:
                self._mouse_queue.put_nowait(("click", (x, y, button, pressed)))
                if pressed:
                    self.stats["allowed_clicks"] += 1
            except queue.Full:
                self.stats["dropped_events"] += 1
        else:  # DENY
            if pressed:
                self.stats["blocked_clicks"] += 1
                action = "pressed" if pressed else "released"
                self._log(f"[BLOCKED] Remote mouse {action}: {button} at ({x}, {y}) (Reason: {decision})")

    def _on_move(self, x, y, injected):
        """Mouse move callback"""
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
                if event_type == "press":
                    self._keyboard_controller.press(key)
                elif event_type == "release":
                    self._keyboard_controller.release(key)
            except queue.Empty:
                continue
            except Exception as e:
                self._log(f"[ERROR] Keyboard worker error: {e}")

    def _mouse_worker(self):
        """Worker thread to re-emit mouse events from host"""
        while not self._stop_event.is_set():
            try:
                event_type, args = self._mouse_queue.get(timeout=WORKER_TIMEOUT)
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
            except queue.Empty:
                continue
            except Exception as e:
                self._log(f"[ERROR] Mouse worker error: {e}")

    # ========================================================================
    # PUBLIC METHODS
    # ========================================================================

    def start(self):
        """Activate selective input blocking"""
        if self._active:
            self._log("[GATEKEEPER] Already active")
            return

        self._log("[GATEKEEPER] Starting input firewall...")
        self._active = True
        self._stop_event.clear()

        # 1. Build device whitelist using Raw Input API
        self._device_whitelist = win32_raw_input.build_device_whitelist(HYPERVISOR_IDENTIFIERS, self._log)
        if not self._device_whitelist:
            self._log("[GATEKEEPER] WARNING: No hypervisor devices found. All input may be blocked.")

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

        self._log("[GATEKEEPER] Input firewall INACTIVE - all input restored")

    def is_active(self):
        """Check if firewall is currently active"""
        return self._active

    def get_stats(self):
        """Get statistics about blocked/allowed events"""
        return self.stats.copy()
