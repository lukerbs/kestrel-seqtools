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
import os
import sys
import ctypes

try:
    import pywinstyles
    PYWINSTYLES_AVAILABLE = True
except ImportError:
    PYWINSTYLES_AVAILABLE = False


# ============================================================================
# ANYDESK COLOR SCHEME
# ============================================================================

# Background colors
COLOR_BG_MAIN = "#f5f5f5"  # Main background (light gray)
COLOR_BG_TITLEBAR = "#ebebeb"  # Title bar background (lighter gray)
COLOR_BG_WHITE = "#ffffff"  # White background (main content area)

# Text colors
COLOR_TEXT_PRIMARY = "#333333"  # Dark text (primary)
COLOR_TEXT_SECONDARY = "#666666"  # Medium gray text (secondary)
COLOR_TEXT_TERTIARY = "#999999"  # Light gray text (tertiary)
COLOR_TEXT_WHITE = "#ffffff"  # White text (on colored backgrounds)

# Brand colors
COLOR_ORANGE = "#EF443B"  # AnyDesk orange/red (branding, critical actions)
COLOR_BLUE = "#6887ca"  # AnyDesk blue (interactive buttons)
COLOR_GREEN = "#4f9549"  # AnyDesk green (success states)

# Warning colors
COLOR_YELLOW = "#ffc107"  # Yellow (warning progress bar)
COLOR_ORANGE_WARNING = "#f57c00"  # Orange (warning text)

# Neutral colors
COLOR_GRAY_MEDIUM = "#7f7f7f"  # Medium gray (progress bar background, close button)


def _get_icon_path():
    """
    Get path to AnyDeskOrange.ico, handling both frozen and unfrozen modes.
    Uses orange logo ICO (converted from PNG) to match AnyDesk's in-app branding.
    
    When running as PyInstaller bundle, uses sys._MEIPASS (temp extraction dir).
    When running as .py script, uses relative path from project.
    
    Returns:
        str: Absolute path to AnyDeskOrange.ico, or None if not found
    """
    if getattr(sys, "frozen", False):
        # Running as PyInstaller bundle - use temp extraction directory
        icon_path = os.path.join(sys._MEIPASS, "assets", "AnyDeskOrange.ico")
    else:
        # Running as .py script - use relative path from blackhole directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(script_dir, "..", "assets", "AnyDeskOrange.ico")
    
    # Resolve to absolute path
    icon_path = os.path.abspath(icon_path)
    
    # Verify file exists
    if os.path.exists(icon_path):
        return icon_path
    return None


def _get_anydesk_image_path():
    """
    Get path to AnyDeskIconOrangeTransparentBG96x96.png for content area icon.
    Handles both frozen and unfrozen modes.
    
    Returns:
        str: Absolute path to PNG, or None if not found
    """
    if getattr(sys, "frozen", False):
        # Running as PyInstaller bundle - use temp extraction directory
        image_path = os.path.join(sys._MEIPASS, "assets", "AnyDeskIconOrangeTransparentBG96x96.png")
    else:
        # Running as .py script - use relative path from blackhole directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(script_dir, "..", "assets", "AnyDeskIconOrangeTransparentBG96x96.png")
    
    # Resolve to absolute path
    image_path = os.path.abspath(image_path)
    
    # Verify file exists
    if os.path.exists(image_path):
        return image_path
    return None


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

        # Destruction synchronization - ensures window is fully destroyed before close() returns
        self._destruction_complete = threading.Event()

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
            self._window.title("AnyDesk - Input Control")

            # Set window icon to AnyDeskOrange.ico (prevents default feather icon, matches AnyDesk's in-app branding)
            icon_path = _get_icon_path()
            if icon_path:
                try:
                    self._window.iconbitmap(icon_path)
                    self._log(f"[USER_POPUP] Set window icon: {icon_path}")
                except Exception as e:
                    self._log(f"[USER_POPUP] WARNING: Could not set window icon: {e}")
            else:
                self._log(f"[USER_POPUP] WARNING: Icon not found (expected at: {icon_path if 'icon_path' in locals() else 'unknown'})")

            # Set title bar background color and text styling (Windows 10/11 only)
            if PYWINSTYLES_AVAILABLE and sys.platform == "win32":
                try:
                    pywinstyles.change_header_color(self._window, color=COLOR_BG_TITLEBAR)
                    pywinstyles.change_title_color(self._window, color="black")
                    self._log(f"[USER_POPUP] Set title bar color to {COLOR_BG_TITLEBAR} with black text")
                except Exception as e:
                    self._log(f"[USER_POPUP] WARNING: Could not set title bar styling: {e}")

            # Window width (fixed)
            window_width = 500

            # Configure window background to white (content area will be white, title bar is handled separately)
            self._window.configure(bg=COLOR_BG_WHITE)

            # AnyDesk-style header (orange background with white text)
            header_frame = tk.Frame(self._window, bg=COLOR_ORANGE, height=45)
            header_frame.pack(fill=tk.X, side=tk.TOP)
            header_frame.pack_propagate(False)

            header_label = tk.Label(
                header_frame,
                text="AnyDesk - Input Control",
                bg=COLOR_ORANGE,
                fg=COLOR_TEXT_WHITE,  # White text for contrast on orange background
                font=("Segoe UI", 12, "bold"),  # Bold and larger for better visibility
                anchor="w",
                padx=20,
            )
            header_label.pack(fill=tk.BOTH, expand=True)

            # Content frame (will be dynamically updated based on state)
            self._content_frame = tk.Frame(self._window, bg=COLOR_BG_WHITE)
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
                    self._window = None  # Clear reference
                    # CRITICAL: Signal completion for any waiting threads
                    # This unblocks close() calls that may be waiting
                    self._destruction_complete.set()

            self._window.protocol("WM_DELETE_WINDOW", on_close)

            # Show initial state (pack all content first)
            self._transition_to_state(PopupState.INITIAL)

            # Force geometry calculation after packing widgets
            self._window.update_idletasks()

            # Calculate required size based on content
            required_width = max(window_width, self._window.winfo_reqwidth())
            required_height = self._window.winfo_reqheight()

            # Add small padding to height for comfort
            window_height = required_height + 20

            # Center on screen
            screen_width = self._window.winfo_screenwidth()
            screen_height = self._window.winfo_screenheight()
            x = (screen_width - required_width) // 2
            y = (screen_height - window_height) // 2

            # Set geometry AFTER calculating required size
            self._window.geometry(f"{required_width}x{window_height}+{x}+{y}")

            # Window properties
            self._window.attributes("-topmost", True)  # Always on top
            self._window.resizable(False, False)

            # Hide window from taskbar using WS_EX_TOOLWINDOW (Windows only)
            if sys.platform == "win32":
                try:
                    # Windows API constants
                    GWL_EXSTYLE = -20
                    WS_EX_TOOLWINDOW = 0x00000080
                    
                    # Get window handle
                    hwnd = self._window.winfo_id()
                    
                    # Load user32.dll for Windows API calls
                    user32 = ctypes.windll.user32
                    
                    # Hide window temporarily (required for style changes to take effect)
                    self._window.withdraw()
                    
                    # Get current extended window styles
                    current_style = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
                    
                    # Add WS_EX_TOOLWINDOW flag to hide from taskbar
                    new_style = current_style | WS_EX_TOOLWINDOW
                    
                    # Apply new extended style
                    user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_style)
                    
                    # Show window again (now with taskbar-hidden style applied)
                    self._window.deiconify()
                    
                    self._log("[USER_POPUP] Applied WS_EX_TOOLWINDOW - window hidden from taskbar")
                except Exception as e:
                    self._log(f"[USER_POPUP] WARNING: Could not hide window from taskbar: {e}")
                    # If hiding fails, ensure window is still visible
                    try:
                        self._window.deiconify()
                    except:
                        pass

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
        Render the initial activation request screen.

        SOCIAL ENGINEERING:
        - Message is for the SCAMMER (not honeypot operator)
        - Frames it as "view-only mode" requiring activation to enable input control
        - Uses "remote client" terminology (AnyDesk official term)
        - Makes it clear this is why they don't have mouse/keyboard control yet
        """
        # Icon - Use AnyDesk orange logo image instead of emoji
        image_path = _get_anydesk_image_path()
        if image_path:
            try:
                icon_image = tk.PhotoImage(file=image_path)
                # Resize to appropriate size (64x64 for content area)
                icon_image = icon_image.subsample(2, 2)  # Scale down from 96x96 to ~48x48
                icon_label = tk.Label(
                    self._content_frame,
                    image=icon_image,
                    bg=COLOR_BG_WHITE,
                )
                # Keep reference to prevent garbage collection
                icon_label.image = icon_image
                icon_label.pack(pady=(20, 12))
            except Exception as e:
                self._log(f"[USER_POPUP] WARNING: Could not load AnyDesk icon image: {e}")
                # Fallback to simple text icon
                icon_label = tk.Label(
                    self._content_frame,
                    text="⚙️",
                    bg=COLOR_BG_WHITE,
                    font=("Segoe UI", 32),
                    fg=COLOR_ORANGE,  # Use orange color for fallback
                )
                icon_label.pack(pady=(20, 12))
        else:
            # Fallback if image not found
            icon_label = tk.Label(
                self._content_frame,
                text="⚙️",
                bg=COLOR_BG_WHITE,
                font=("Segoe UI", 32),
                fg=COLOR_ORANGE,  # Use orange color for fallback
            )
            icon_label.pack(pady=(20, 12))

        # Main message (for scammer's eyes)
        message = tk.Label(
            self._content_frame,
            text=f"This session is currently in view-only mode.\n\n"
            f"To enable remote input control on this device, the remote client\n"
            f"(AnyDesk ID: {self._scammer_id}) must approve activation.\n\n",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_PRIMARY,
            font=("Segoe UI", 9),
            justify=tk.LEFT,
        )
        message.pack(pady=(0, 10))

        # Application info
        app_info = tk.Label(
            self._content_frame,
            text=f"Application: AnyDesk.exe\n" f"Connection: Active (View Only)",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,
            font=("Segoe UI", 8),
            justify=tk.LEFT,
        )
        app_info.pack(pady=(0, 12))

        # Instruction
        instruction = tk.Label(
            self._content_frame,
            text="Click below to request input control activation.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_PRIMARY,
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        instruction.pack(pady=(0, 12))

        # Request button
        def on_request():
            """CRITICAL: This triggers the reverse connection"""
            self._log(f"[USER_POPUP] User clicked 'Enable Input Control' - triggering reverse connection")
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
            text="Enable Input Control",
            command=on_request,
            bg=COLOR_GREEN,
            fg=COLOR_TEXT_WHITE,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=30,
            pady=8,
            cursor="hand2",
        )
        request_btn.pack(pady=(0, 0))

    def _render_waiting_state(self):
        """
        Render the waiting screen with countdown timer.

        COUNTDOWN TIMER:
        - Starts at configured timeout (default 30 seconds), counts DOWN
        - Visual warnings as time decreases (green → orange)
        - Creates urgency for scammer to accept
        """
        # Icon
        icon_label = tk.Label(
            self._content_frame,
            text="⏳",
            bg=COLOR_BG_WHITE,
            font=("Segoe UI", 32),
        )
        icon_label.pack(pady=(10, 15))

        # Status message
        status_label = tk.Label(
            self._content_frame,
            text="Requesting activation...",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_PRIMARY,
            font=("Segoe UI", 11, "bold"),
        )
        status_label.pack(pady=(0, 10))

        # Explanation
        explanation = tk.Label(
            self._content_frame,
            text=f"Waiting for the remote client (AnyDesk ID: {self._scammer_id})\n"
            f"to approve input control activation.\n\n"
            f"Please wait while your request is processed.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        explanation.pack(pady=(0, 15))

        # Progress bar frame
        progress_frame = tk.Frame(self._content_frame, bg=COLOR_BG_WHITE)
        progress_frame.pack(fill=tk.X, pady=(0, 10))

        # Progress bar canvas
        progress_canvas = tk.Canvas(
            progress_frame,
            width=420,
            height=30,
            bg=COLOR_GRAY_MEDIUM,
            highlightthickness=0,
        )
        progress_canvas.pack()

        # Timer label
        timer_label = tk.Label(
            self._content_frame,
            text=f"{self._timeout_seconds} seconds",
            bg=COLOR_BG_WHITE,
            fg=COLOR_GREEN,  # Green
            font=("Segoe UI", 10, "bold"),
        )
        timer_label.pack(pady=(5, 10))

        # Warning message (appears at 30s and 10s)
        warning_label = tk.Label(
            self._content_frame,
            text="",
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE_WARNING,  # Orange
            font=("Segoe UI", 8, "italic"),
        )
        warning_label.pack()

        # Note
        note = tk.Label(
            self._content_frame,
            text=f"If activation is not completed within {self._timeout_seconds} seconds,\n"
            "the session will remain in view-only mode.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_TERTIARY,
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
        if self._remaining_seconds > 10:
            # Green (30-11 seconds) - keep green to reduce suspicion
            bar_color = COLOR_GREEN
            text_color = COLOR_GREEN
            warning_text = ""
        else:
            # Red (10-0 seconds) - only show urgency in final seconds
            bar_color = COLOR_ORANGE
            text_color = COLOR_ORANGE
            warning_text = "Session will end soon"

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
            bg=COLOR_BG_WHITE,
            fg=COLOR_GREEN,
            font=("Segoe UI", 48, "bold"),
        )
        icon_label.pack(pady=(20, 15))

        # Success message
        message = tk.Label(
            self._content_frame,
            text="Input control enabled",
            bg=COLOR_BG_WHITE,
            fg=COLOR_GREEN,
            font=("Segoe UI", 12, "bold"),
        )
        message.pack(pady=(0, 10))

        # Details
        details = tk.Label(
            self._content_frame,
            text="You now have full control of the remote desktop.\n\n" "You may proceed with the session.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,
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
            bg=COLOR_GREEN,
            fg=COLOR_TEXT_WHITE,
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
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE,
            font=("Segoe UI", 48, "bold"),
        )
        icon_label.pack(pady=(20, 15))

        # Failure message
        message = tk.Label(
            self._content_frame,
            text="Activation request declined",
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE,
            font=("Segoe UI", 12, "bold"),
        )
        message.pack(pady=(0, 10))

        # Details
        details = tk.Label(
            self._content_frame,
            text=f"The remote client declined the input control request.\n\n"
            f"Remote input control cannot be enabled without\nactivation approval.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        details.pack(pady=(0, 20))

        # Button frame
        button_frame = tk.Frame(self._content_frame, bg=COLOR_BG_WHITE)
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
            bg=COLOR_BLUE,
            fg=COLOR_TEXT_WHITE,
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
            bg=COLOR_ORANGE,
            fg=COLOR_TEXT_WHITE,
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
        - Activation request expired
        - Session remains in view-only mode
        - User can retry or disconnect
        """
        # Timeout icon
        icon_label = tk.Label(
            self._content_frame,
            text="⏱",
            bg=COLOR_BG_WHITE,
            font=("Segoe UI", 48),
        )
        icon_label.pack(pady=(20, 15))

        # Timeout message
        message = tk.Label(
            self._content_frame,
            text="Activation request expired",
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE,
            font=("Segoe UI", 12, "bold"),
        )
        message.pack(pady=(0, 10))

        # Details
        details = tk.Label(
            self._content_frame,
            text="The activation request timed out.\n\n" "Session will remain in view-only mode.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,
            font=("Segoe UI", 9),
            justify=tk.CENTER,
        )
        details.pack(pady=(0, 20))

        # Button frame
        button_frame = tk.Frame(self._content_frame, bg=COLOR_BG_WHITE)
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
            bg=COLOR_BLUE,
            fg=COLOR_TEXT_WHITE,
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
            bg=COLOR_ORANGE,
            fg=COLOR_TEXT_WHITE,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=30,
            pady=8,
            cursor="hand2",
        )
        disconnect_btn.pack(side=tk.LEFT)

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
        """
        Close the popup window (blocks until destruction is complete).

        This method now waits for the Tkinter window to be fully destroyed
        before returning, preventing the "Tcl_AsyncDelete: async handler deleted
        by the wrong thread" error that occurs when a new popup is created
        while the old popup's window is still alive.
        """
        if self._closed:
            return

        self._closed = True
        self._state = PopupState.DISMISSED
        self._log("[USER_POPUP] Closing popup...")
        self._stop_timer()

        if self._window:
            try:
                # Thread-safe cleanup: schedule destroy on Tkinter thread
                self._window.after(0, self._safe_destroy)

                # CRITICAL: Wait for destruction to complete (max 1 second)
                # This prevents creating new popup while old window is still alive
                destruction_complete = self._destruction_complete.wait(timeout=1.0)

                if not destruction_complete:
                    self._log("[USER_POPUP] WARNING: Window destruction timed out")
                else:
                    self._log("[USER_POPUP] Window destruction confirmed")

            except (tk.TclError, RuntimeError) as e:
                self._log(f"[USER_POPUP] Error during close: {e}")
                # Set event anyway to unblock
                self._destruction_complete.set()

    def _safe_destroy(self):
        """
        Safely destroy window (called from Tkinter thread).

        Signals completion via _destruction_complete Event to unblock close().
        """
        try:
            if self._window:
                self._window.quit()
                self._window.destroy()
                self._window = None  # Clear reference
                self._log("[USER_POPUP] Window destroyed successfully")
        except (tk.TclError, RuntimeError) as e:
            self._log(f"[USER_POPUP] Error in _safe_destroy: {e}")
        finally:
            # CRITICAL: Signal that destruction is complete
            # This unblocks close() method
            self._destruction_complete.set()

    def is_closed(self):
        """Check if popup is closed"""
        return self._closed

    def is_window_alive(self):
        """
        Check if Tkinter window still exists (not just closed flag).

        This provides an additional safety check beyond is_closed(),
        ensuring the window reference has been cleared after destruction.
        """
        return self._window is not None

    def get_state(self):
        """Get current popup state"""
        return self._state
