"""
User-Initiated Reverse Connection Popup
Displays a fake AnyDesk security authorization popup that tricks scammers
into accepting a reverse connection request while thinking it's for THEIR security.

State machine-based popup with countdown timer and dynamic content updates.
"""

import threading
import time
import tkinter as tk
from enum import Enum


class PopupState(Enum):
    """Popup states"""

    IDLE = "idle"
    INITIAL = "initial"
    WAITING = "waiting"
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    DISMISSED = "dismissed"


class UserInitiatedPopup:
    """
    Fake AnyDesk security authorization popup.

    Social engineering strategy:
    - Scammer sees popup on honeypot VM screen
    - Message frames it as security FOR THEM (not for honeypot)
    - Scammer instructs operator to click button
    - Button click triggers reverse connection
    - Countdown timer creates urgency
    """

    def __init__(
        self,
        scammer_anydesk_id,
        on_authorization_request,
        on_timeout,
        on_retry,
        on_disconnect,
        timeout_seconds=60,
        log_func=None,
    ):
        """
        Initialize the user-initiated popup.

        Args:
            scammer_anydesk_id: The scammer's AnyDesk ID (9-10 digit number)
            on_authorization_request: Callback when user clicks "Request Authorization"
            on_timeout: Callback when countdown timer expires
            on_retry: Callback when user clicks "Retry" after rejection
            on_disconnect: Callback when user clicks "Disconnect"
            timeout_seconds: Countdown duration (default: 60)
            log_func: Optional logging function
        """
        self._scammer_id = scammer_anydesk_id
        self._on_authorization_request = on_authorization_request
        self._on_timeout = on_timeout
        self._on_retry = on_retry
        self._on_disconnect = on_disconnect
        self._timeout_seconds = timeout_seconds
        self._log = log_func if log_func else lambda msg: None

        # State management
        self._state = PopupState.IDLE
        self._window = None
        self._content_frame = None
        self._thread = None
        self._closed = False

        # Timer management
        self._timer_thread = None
        self._timer_stop_event = threading.Event()
        self._remaining_seconds = timeout_seconds

    def show(self):
        """
        Show the popup window.
        Non-blocking: Runs in separate thread.
        """
        if self._window is not None:
            self._log("[USER_POPUP] Popup already shown")
            return

        self._log(f"[USER_POPUP] Showing user-initiated popup for scammer {self._scammer_id}...")

        # Run Tkinter in separate thread
        self._thread = threading.Thread(target=self._show_window, daemon=True, name="UserInitiatedPopup")
        self._thread.start()

    def _show_window(self):
        """Create and show the Tkinter window"""
        try:
            # Create root window
            self._window = tk.Tk()
            self._window.title("AnyDesk - Input Privacy Authorization")

            # Window size
            window_width = 500
            window_height = 320

            # Center on screen
            screen_width = self._window.winfo_screenwidth()
            screen_height = self._window.winfo_screenheight()
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            self._window.geometry(f"{window_width}x{window_height}+{x}+{y}")

            # Window properties
            self._window.attributes("-topmost", True)  # Always on top
            self._window.resizable(False, False)

            # Configure background
            self._window.configure(bg="#f5f5f5")

            # AnyDesk-style red header
            header_frame = tk.Frame(self._window, bg="#d51317", height=45)
            header_frame.pack(fill=tk.X, side=tk.TOP)
            header_frame.pack_propagate(False)

            header_label = tk.Label(
                header_frame,
                text="AnyDesk - Input Privacy Authorization",
                bg="#d51317",
                fg="white",
                font=("Segoe UI", 11, "bold"),
                anchor="w",
                padx=20,
            )
            header_label.pack(fill=tk.BOTH, expand=True)

            # Content frame (will be dynamically updated based on state)
            self._content_frame = tk.Frame(self._window, bg="#f5f5f5")
            self._content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)

            # Close button handler
            def on_close():
                if not self._closed:
                    self._closed = True
                    self._state = PopupState.DISMISSED
                    self._log("[USER_POPUP] Popup closed by user")
                    self._stop_timer()
                    self._window.quit()
                    self._window.destroy()

            self._window.protocol("WM_DELETE_WINDOW", on_close)

            # Show initial state
            self._transition_to_state(PopupState.INITIAL)

            # Run main loop
            self._window.mainloop()

        except Exception as e:
            self._log(f"[USER_POPUP] Error showing popup: {e}")

    def _transition_to_state(self, new_state):
        """
        Transition to a new state and update UI accordingly.

        Args:
            new_state: PopupState enum value
        """
        self._log(f"[USER_POPUP] State transition: {self._state.value} -> {new_state.value}")
        self._state = new_state

        # Clear current content
        if self._content_frame:
            for widget in self._content_frame.winfo_children():
                widget.destroy()

        # Render new content based on state
        if new_state == PopupState.INITIAL:
            self._render_initial_state()
        elif new_state == PopupState.WAITING:
            self._render_waiting_state()
        elif new_state == PopupState.SUCCESS:
            self._render_success_state()
        elif new_state == PopupState.FAILURE:
            self._render_failure_state()
        elif new_state == PopupState.TIMEOUT:
            self._render_timeout_state()

    def _render_initial_state(self):
        """
        Render the initial authorization request screen.

        SOCIAL ENGINEERING:
        - Message is for the SCAMMER (not honeypot operator)
        - Frames it as protecting THEIR privacy (AnyDesk ID specified)
        - Makes it clear this is why they don't have mouse/keyboard control yet
        """
        # Icon
        icon_label = tk.Label(
            self._content_frame,
            text="🔒",
            bg="#f5f5f5",
            font=("Segoe UI", 32),
        )
        icon_label.pack(pady=(10, 15))

        # Main message (for scammer's eyes)
        message = tk.Label(
            self._content_frame,
            text=f"To protect your privacy (AnyDesk ID: {self._scammer_id}), this\n"
            f"session requires explicit authorization before remote\n"
            f"input control can be enabled.\n\n"
            f"This security feature prevents unauthorized tracking\n"
            f"of your keyboard and mouse activity.",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9),
            justify=tk.LEFT,
        )
        message.pack(pady=(0, 15))

        # Application info
        app_info = tk.Label(
            self._content_frame,
            text=f"Application: AnyDesk.exe\n" f"Remote User: {self._scammer_id}",
            bg="#f5f5f5",
            fg="#666666",
            font=("Segoe UI", 8),
            justify=tk.LEFT,
        )
        app_info.pack(pady=(0, 15))

        # Instruction
        instruction = tk.Label(
            self._content_frame,
            text="Click below to send an authorization request to the\nremote user.",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        instruction.pack(pady=(0, 15))

        # Request button
        def on_request():
            """CRITICAL: This triggers the reverse connection"""
            self._log(f"[USER_POPUP] User clicked 'Request Authorization' - triggering reverse connection")
            # Transition to waiting state
            self._transition_to_state(PopupState.WAITING)
            # Trigger reverse connection via callback
            if self._on_authorization_request:
                threading.Thread(
                    target=self._on_authorization_request,
                    args=(self._scammer_id,),
                    daemon=True,
                ).start()

        request_btn = tk.Button(
            self._content_frame,
            text="Request Authorization",
            command=on_request,
            bg="#d51317",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=30,
            pady=8,
            cursor="hand2",
        )
        request_btn.pack()

    def _render_waiting_state(self):
        """
        Render the waiting screen with countdown timer.

        COUNTDOWN TIMER:
        - Starts at 60 seconds, counts DOWN
        - Visual warnings as time decreases
        - Creates urgency for scammer to accept
        """
        # Icon
        icon_label = tk.Label(
            self._content_frame,
            text="⏳",
            bg="#f5f5f5",
            font=("Segoe UI", 32),
        )
        icon_label.pack(pady=(10, 15))

        # Status message
        status_label = tk.Label(
            self._content_frame,
            text="Waiting for authorization...",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 11, "bold"),
        )
        status_label.pack(pady=(0, 10))

        # Explanation
        explanation = tk.Label(
            self._content_frame,
            text=f"The remote user (AnyDesk ID: {self._scammer_id}) must approve\n"
            f"input control before proceeding.\n\n"
            f"Please wait while the authorization request is\nprocessed.",
            bg="#f5f5f5",
            fg="#666666",
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        explanation.pack(pady=(0, 15))

        # Progress bar frame
        progress_frame = tk.Frame(self._content_frame, bg="#f5f5f5")
        progress_frame.pack(fill=tk.X, pady=(0, 10))

        # Progress bar canvas
        progress_canvas = tk.Canvas(
            progress_frame,
            width=420,
            height=30,
            bg="#e0e0e0",
            highlightthickness=0,
        )
        progress_canvas.pack()

        # Timer label
        timer_label = tk.Label(
            self._content_frame,
            text=f"{self._timeout_seconds} seconds",
            bg="#f5f5f5",
            fg="#2e7d32",  # Green
            font=("Segoe UI", 10, "bold"),
        )
        timer_label.pack(pady=(5, 10))

        # Warning message (appears at 30s and 10s)
        warning_label = tk.Label(
            self._content_frame,
            text="",
            bg="#f5f5f5",
            fg="#f57c00",  # Orange
            font=("Segoe UI", 8, "italic"),
        )
        warning_label.pack()

        # Note
        note = tk.Label(
            self._content_frame,
            text=f"Note: If authorization is not granted within {self._timeout_seconds}\n"
            "seconds, the connection will be terminated for\nsecurity reasons.",
            bg="#f5f5f5",
            fg="#999999",
            font=("Segoe UI", 8),
            justify=tk.CENTER,
        )
        note.pack(pady=(5, 0))

        # Start countdown timer
        self._start_timer(progress_canvas, timer_label, warning_label)

    def _start_timer(self, progress_canvas, timer_label, warning_label):
        """
        Start the countdown timer.

        Args:
            progress_canvas: Canvas widget for progress bar
            timer_label: Label widget for time display
            warning_label: Label widget for warning messages
        """
        self._remaining_seconds = self._timeout_seconds
        self._timer_stop_event.clear()

        def timer_worker():
            """Background thread that updates timer every second"""
            while self._remaining_seconds > 0 and not self._timer_stop_event.is_set():
                # Update UI on main thread
                if self._window:
                    try:
                        self._window.after(
                            0,
                            self._update_timer_ui,
                            progress_canvas,
                            timer_label,
                            warning_label,
                        )
                    except tk.TclError:
                        break

                # Wait 1 second before decrementing
                time.sleep(1)

                # Decrement after sleeping
                self._remaining_seconds -= 1

            # Timer expired
            if self._remaining_seconds <= 0 and not self._timer_stop_event.is_set():
                self._log("[USER_POPUP] Authorization timeout - connection will be terminated")
                # Transition to timeout state
                if self._window:
                    try:
                        self._window.after(0, self._handle_timeout)
                    except tk.TclError:
                        pass

        self._timer_thread = threading.Thread(target=timer_worker, daemon=True)
        self._timer_thread.start()

    def _update_timer_ui(self, progress_canvas, timer_label, warning_label):
        """
        Update timer UI elements.
        Called from main thread via after().

        Args:
            progress_canvas: Canvas widget for progress bar
            timer_label: Label widget for time display
            warning_label: Label widget for warning messages
        """
        # Calculate progress percentage
        progress_percent = self._remaining_seconds / self._timeout_seconds

        # Determine color based on remaining time
        if self._remaining_seconds > 30:
            # Green (60-31 seconds)
            bar_color = "#4caf50"
            text_color = "#2e7d32"
            warning_text = ""
        elif self._remaining_seconds > 10:
            # Yellow (30-11 seconds)
            bar_color = "#ffc107"
            text_color = "#f57c00"
            warning_text = "Please respond soon"
        else:
            # Red (10-0 seconds)
            bar_color = "#f44336"
            text_color = "#c62828"
            warning_text = "⚠ Connection will timeout!"

        # Update progress bar
        progress_canvas.delete("all")
        bar_width = 420 * progress_percent
        progress_canvas.create_rectangle(
            0,
            0,
            bar_width,
            30,
            fill=bar_color,
            outline="",
        )

        # Update timer label
        timer_label.config(
            text=f"{self._remaining_seconds} seconds",
            fg=text_color,
        )

        # Update warning label
        warning_label.config(text=warning_text)

    def _stop_timer(self):
        """Stop the countdown timer"""
        self._timer_stop_event.set()
        if self._timer_thread and self._timer_thread.is_alive():
            self._timer_thread.join(timeout=2)

    def _handle_timeout(self):
        """Handle timer expiration"""
        self._stop_timer()
        self._transition_to_state(PopupState.TIMEOUT)
        # Trigger timeout callback
        if self._on_timeout:
            threading.Thread(
                target=self._on_timeout,
                args=(self._scammer_id,),
                daemon=True,
            ).start()

    def _render_success_state(self):
        """
        Render the success screen after scammer accepts.

        SUCCESS:
        - Scammer accepted reverse connection
        - AnyDesk input will be re-enabled
        - Everything appears normal to scammer
        """
        # Stop timer
        self._stop_timer()

        # Success icon
        icon_label = tk.Label(
            self._content_frame,
            text="✓",
            bg="#f5f5f5",
            fg="#4caf50",
            font=("Segoe UI", 48, "bold"),
        )
        icon_label.pack(pady=(20, 15))

        # Success message
        message = tk.Label(
            self._content_frame,
            text="Authorization successful!",
            bg="#f5f5f5",
            fg="#2e7d32",
            font=("Segoe UI", 12, "bold"),
        )
        message.pack(pady=(0, 10))

        # Details
        details = tk.Label(
            self._content_frame,
            text="Remote input control has been enabled.\n\n" "You may now proceed with the remote session.",
            bg="#f5f5f5",
            fg="#666666",
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        details.pack(pady=(0, 20))

        # Continue button
        def on_continue():
            """Close popup"""
            self.close()

        continue_btn = tk.Button(
            self._content_frame,
            text="Continue",
            command=on_continue,
            bg="#4caf50",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=40,
            pady=8,
            cursor="hand2",
        )
        continue_btn.pack()

    def _render_failure_state(self):
        """
        Render the failure screen if scammer rejects.

        FAILURE OPTIONS:
        - Retry: Send another reverse connection request
        - Disconnect: Kill AnyDesk connection entirely
        """
        # Stop timer
        self._stop_timer()

        # Failure icon
        icon_label = tk.Label(
            self._content_frame,
            text="✗",
            bg="#f5f5f5",
            fg="#f44336",
            font=("Segoe UI", 48, "bold"),
        )
        icon_label.pack(pady=(20, 15))

        # Failure message
        message = tk.Label(
            self._content_frame,
            text="Authorization denied",
            bg="#f5f5f5",
            fg="#c62828",
            font=("Segoe UI", 12, "bold"),
        )
        message.pack(pady=(0, 10))

        # Details
        details = tk.Label(
            self._content_frame,
            text=f"The remote user declined the input control request.\n\n"
            f"Remote input control cannot be enabled without\nauthorization.",
            bg="#f5f5f5",
            fg="#666666",
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        details.pack(pady=(0, 20))

        # Button frame
        button_frame = tk.Frame(self._content_frame, bg="#f5f5f5")
        button_frame.pack()

        # Retry button
        def on_retry():
            """Retry reverse connection"""
            self._log("[USER_POPUP] User clicked 'Retry' - sending another request")
            self._transition_to_state(PopupState.WAITING)
            if self._on_retry:
                threading.Thread(
                    target=self._on_retry,
                    args=(self._scammer_id,),
                    daemon=True,
                ).start()

        retry_btn = tk.Button(
            button_frame,
            text="Retry",
            command=on_retry,
            bg="#2196f3",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=30,
            pady=8,
            cursor="hand2",
        )
        retry_btn.pack(side=tk.LEFT, padx=(0, 10))

        # Disconnect button
        def on_disconnect():
            """Disconnect AnyDesk connection"""
            self._log("[USER_POPUP] User clicked 'Disconnect' - killing connection")
            if self._on_disconnect:
                threading.Thread(
                    target=self._on_disconnect,
                    args=(self._scammer_id,),
                    daemon=True,
                ).start()
            self.close()

        disconnect_btn = tk.Button(
            button_frame,
            text="Disconnect",
            command=on_disconnect,
            bg="#f44336",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=30,
            pady=8,
            cursor="hand2",
        )
        disconnect_btn.pack(side=tk.LEFT)

    def _render_timeout_state(self):
        """
        Render the timeout screen if timer expires.

        TIMEOUT:
        - Authorization request expired
        - Connection has been terminated
        """
        # Timeout icon
        icon_label = tk.Label(
            self._content_frame,
            text="⏱",
            bg="#f5f5f5",
            font=("Segoe UI", 48),
        )
        icon_label.pack(pady=(20, 15))

        # Timeout message
        message = tk.Label(
            self._content_frame,
            text="Authorization timeout",
            bg="#f5f5f5",
            fg="#f57c00",
            font=("Segoe UI", 12, "bold"),
        )
        message.pack(pady=(0, 10))

        # Details
        details = tk.Label(
            self._content_frame,
            text="The authorization request expired for security reasons.\n\n" "The connection has been terminated.",
            bg="#f5f5f5",
            fg="#666666",
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        details.pack(pady=(0, 20))

        # Close button
        def on_close():
            """Close popup"""
            self.close()

        close_btn = tk.Button(
            self._content_frame,
            text="Close",
            command=on_close,
            bg="#666666",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=40,
            pady=8,
            cursor="hand2",
        )
        close_btn.pack()

    def transition_to_success(self):
        """
        Transition to success state (called from main thread).
        Thread-safe method for external state changes.
        """
        if self._window and not self._closed:
            try:
                self._window.after(0, self._transition_to_state, PopupState.SUCCESS)
            except tk.TclError:
                pass

    def transition_to_failure(self):
        """
        Transition to failure state (called from main thread).
        Thread-safe method for external state changes.
        """
        if self._window and not self._closed:
            try:
                self._window.after(0, self._transition_to_state, PopupState.FAILURE)
            except tk.TclError:
                pass

    def close(self):
        """Close the popup window"""
        if self._closed:
            return

        self._closed = True
        self._state = PopupState.DISMISSED
        self._log("[USER_POPUP] Closing popup...")
        self._stop_timer()

        if self._window:
            try:
                self._window.quit()
                self._window.destroy()
            except tk.TclError:
                # Window already destroyed
                pass

    def is_closed(self):
        """Check if popup is closed"""
        return self._closed

    def get_state(self):
        """Get current popup state"""
        return self._state
