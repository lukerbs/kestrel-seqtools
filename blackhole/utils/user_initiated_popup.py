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

# Button hover colors (slightly darker shades)
COLOR_GREEN_HOVER = "#3a6f35"  # Darker green for button hover
COLOR_BLUE_HOVER = "#5670a0"  # Darker blue for button hover
COLOR_ORANGE_HOVER = "#d03830"  # Darker orange for button hover

# Layout constants
STANDARD_PADX = 24  # Horizontal padding (increased from 20)
STANDARD_PADY = 20  # Vertical padding (increased from 15)
ELEMENT_SPACING = 12  # Space between elements
SECTION_SPACING = 20  # Space between major sections
BUTTON_HEIGHT_PX = 32  # Button height in pixels (from CustomTkinter implementation)

# Typography constants
# Using system fonts with proper sizes for clear rendering
FONT_HEADING = ("Segoe UI", 12, "bold")  # Main headings (reduced from 13 for better rendering)
FONT_BODY = ("Segoe UI", 11)  # Body text (increased from 10 for better readability)
FONT_SECONDARY = ("Segoe UI", 10)  # Secondary info (increased from 9)
FONT_SMALL = ("Segoe UI", 9)  # Very minor details (increased from 8)


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


def _create_button_with_hover(parent, text, command, bg_color, hover_color, **kwargs):
    """
    Create a button with hover effect (darker background on hover).
    Matches AnyDesk's simple flat design with consistent 32px height.
    
    Args:
        parent: Parent widget
        text: Button text
        command: Button command callback
        bg_color: Normal background color
        hover_color: Hover background color (darker shade)
        **kwargs: Additional button options
    
    Returns:
        tk.Button: Configured button with hover effect
    """
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg_color,
        fg=COLOR_TEXT_WHITE,
        font=("Segoe UI", 11, "bold"),  # Bold text like AnyDesk (increased for better rendering)
        relief=tk.FLAT,
        cursor="hand2",
        **kwargs
    )
    
    # Set button height to 1 line with minimal padding for 32px total height
    # Tkinter height is in text lines, so height=1 with pady=2 gives approximately 32px
    btn.config(height=1, pady=2)
    
    # Hover effect: darker background
    def on_enter(e):
        btn.config(bg=hover_color)
    def on_leave(e):
        btn.config(bg=bg_color)
    
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    
    return btn


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
            self._window.title("AnyDesk - Remote Client Connected")
            
            # Window width (increased for better layout)
            window_width = 480

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

            # Configure window background to white (content area will be white, title bar is handled separately)
            self._window.configure(bg=COLOR_BG_WHITE)

            # AnyDesk-style header (orange background with white text)
            header_frame = tk.Frame(self._window, bg=COLOR_ORANGE, height=40)
            header_frame.pack(fill=tk.X, side=tk.TOP)
            header_frame.pack_propagate(False)

            header_label = tk.Label(
                header_frame,
                text="AnyDesk - Remote Client Connected",
                bg=COLOR_ORANGE,
                fg=COLOR_TEXT_WHITE,  # White text for contrast on orange background
                font=FONT_HEADING,  # Use font constant
                anchor="w",
                padx=STANDARD_PADX,  # Match content padding
            )
            header_label.pack(fill=tk.BOTH, expand=True)

            # Content frame (will be dynamically updated based on state)
            self._content_frame = tk.Frame(self._window, bg=COLOR_BG_WHITE)
            self._content_frame.pack(fill=tk.BOTH, expand=True, padx=STANDARD_PADX, pady=STANDARD_PADY)

            # Close button handler
            def on_close():
                if not self._closed:
                    self._closed = True
                    self._state = PopupState.DISMISSED
                    self._log("[USER_POPUP] Popup closed by user")
                    # CRITICAL: Stop timer BEFORE destroying window
                    # This prevents timer thread from queuing callbacks during destruction
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
            window_height = required_height + 10

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

    def _get_available_width(self):
        """
        Get the actual available width for text wrapping in the content frame.
        This is more reliable than calculating from window width.
        
        The content frame has padx=STANDARD_PADX (24px on each side), so the frame
        itself is window_width - (STANDARD_PADX * 2) wide. Labels with fill=tk.X
        will expand to fill this frame width, so wraplength should match the frame width.
        
        Returns:
            int: Available width in pixels for text wrapping
        """
        # Default fallback (480 window - 48 padding = 432)
        available_width = 432
        
        if self._content_frame:
            try:
                # Force update to get accurate width
                self._content_frame.update_idletasks()
                frame_width = self._content_frame.winfo_width()
                
                # winfo_width() returns the widget's internal width, not including padding
                # Since the frame has padx=STANDARD_PADX, the actual content area is
                # the frame width itself (padding is external to the frame)
                if frame_width > 1:
                    available_width = frame_width
                else:
                    # If frame width not yet calculated (returns 1), calculate from window
                    if self._window:
                        self._window.update_idletasks()
                        window_width = self._window.winfo_width()
                        if window_width > 1:
                            # Content frame width = window width minus frame padding (left + right)
                            # The frame has padx=STANDARD_PADX, so subtract STANDARD_PADX * 2
                            available_width = window_width - (STANDARD_PADX * 2)
            except Exception as e:
                # Fallback to default if any error occurs
                pass
        
        return available_width

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
        # Get available width for text wrapping
        available_width = self._get_available_width()
        
        # Main message (for scammer's eyes) - Regular weight, dark for hierarchy
        message = tk.Label(
            self._content_frame,
            text=f"This session is currently in view-only mode.\n\n"
            f"To enable remote input control on this device, the remote client\n"
            f"(AnyDesk ID: {self._scammer_id}) must approve activation.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_PRIMARY,  # Dark text for primary content
            font=FONT_BODY,  # Regular weight, not bold (AnyDesk uses bold sparingly)
            justify=tk.LEFT,
            anchor="w",
            wraplength=available_width,  # Proper text wrapping to fill available width
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        # Application info - Lighter gray, smaller, regular weight
        app_info = tk.Label(
            self._content_frame,
            text=f"Application: AnyDesk.exe\n" f"Connection: Active (View Only)",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,  # Medium gray (increased from tertiary)
            font=FONT_SECONDARY,  # 9px instead of 8px
            justify=tk.LEFT,
            anchor="w",
        )
        app_info.pack(fill=tk.X, pady=(0, ELEMENT_SPACING), anchor="w")

        # Instruction - Medium gray, regular weight
        instruction = tk.Label(
            self._content_frame,
            text="Click below to request input control activation.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,  # Medium gray for secondary text
            font=FONT_SECONDARY,
            justify=tk.LEFT,
            anchor="w",
        )
        instruction.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

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

        request_btn = _create_button_with_hover(
            self._content_frame,
            "Enable Input Control",
            on_request,
            COLOR_GREEN,
            COLOR_GREEN_HOVER,
        )
        request_btn.pack(fill=tk.X, pady=(0, 0))  # Full width button

    def _render_waiting_state(self):
        """
        Render the waiting screen with countdown timer.

        COUNTDOWN TIMER:
        - Starts at configured timeout (default 30 seconds), counts DOWN
        - Visual warnings as time decreases (green → orange)
        - Creates urgency for scammer to accept
        """
        # Get available width for text wrapping
        available_width = self._get_available_width()
        
        # Get window width for progress bar (needs full window width calculation)
        window_width = 480  # Default
        if self._window:
            try:
                self._window.update_idletasks()
                window_width = self._window.winfo_width()
                if window_width <= 1:
                    window_width = 480
            except:
                pass
        
        # Status message - Bold, dark for primary hierarchy
        status_label = tk.Label(
            self._content_frame,
            text="Requesting activation...",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_PRIMARY,  # Dark text for primary content
            font=FONT_HEADING,  # Use heading font
        )
        status_label.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        # Explanation - Regular weight, medium gray
        explanation = tk.Label(
            self._content_frame,
            text=f"Waiting for the remote client (AnyDesk ID: {self._scammer_id})\n"
            f"to approve input control activation.\n\n"
            f"Please wait while your request is processed.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,  # Medium gray for secondary text
            font=FONT_SECONDARY,
            justify=tk.LEFT,
            anchor="w",
            wraplength=available_width,
        )
        explanation.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

        # Progress bar frame
        progress_frame = tk.Frame(self._content_frame, bg=COLOR_BG_WHITE)
        progress_frame.pack(fill=tk.X, pady=(0, ELEMENT_SPACING))

        # Progress bar canvas (dynamic width, slightly smaller height)
        progress_canvas = tk.Canvas(
            progress_frame,
            width=available_width,  # Match content width (same as text wrapping width)
            height=28,  # Slightly smaller (AnyDesk uses compact bars)
            bg="#e0e0e0",  # Light gray background for progress bar
            highlightthickness=0,
        )
        progress_canvas.pack()

        # Timer label
        timer_label = tk.Label(
            self._content_frame,
            text=f"{self._timeout_seconds} seconds",
            bg=COLOR_BG_WHITE,
            fg=COLOR_GREEN,  # Green
            font=("Segoe UI", 11, "bold"),  # Bold for emphasis (increased for better rendering)
        )
        timer_label.pack(pady=(ELEMENT_SPACING // 2, ELEMENT_SPACING))

        # Warning message (appears at 10s)
        warning_label = tk.Label(
            self._content_frame,
            text="",
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE_WARNING,  # Orange
            font=FONT_SMALL,  # Small font
        )
        warning_label.pack()

        # Note - Light gray, smaller, left-aligned
        note = tk.Label(
            self._content_frame,
            text=f"If activation is not completed within {self._timeout_seconds} seconds,\n"
            "the session will remain in view-only mode.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_TERTIARY,  # Light gray for tertiary text
            font=FONT_SMALL,
            justify=tk.LEFT,
            anchor="w",
            wraplength=available_width,  # Ensure proper text wrapping
        )
        note.pack(fill=tk.X, pady=(ELEMENT_SPACING // 2, 0), anchor="w")

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
                # CRITICAL: Check window is alive before scheduling callback
                if not self.is_window_alive():
                    break  # Window destroyed, exit immediately
                
                # Update UI on main thread
                try:
                    # Double-check window is still alive before after()
                    if not self.is_window_alive():
                        break
                    self._window.after(
                        0,
                        self._update_timer_ui,
                        progress_canvas,
                        timer_label,
                        warning_label,
                    )
                except (tk.TclError, RuntimeError):
                    break  # Window destroyed, exit immediately

                # Wait 1 second before decrementing
                time.sleep(1)

                # CRITICAL: Check again after sleep (window might have been destroyed)
                if not self.is_window_alive() or self._timer_stop_event.is_set():
                    break

                # Decrement after sleeping
                self._remaining_seconds -= 1

            # Timer expired or window destroyed
            if self._remaining_seconds <= 0 and not self._timer_stop_event.is_set():
                self._log("[USER_POPUP] Authorization timeout - connection will be terminated")
                # Transition to timeout state
                if self.is_window_alive():
                    try:
                        self._window.after(0, self._handle_timeout)
                    except (tk.TclError, RuntimeError):
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
        # CRITICAL: Check window is still alive before accessing widgets
        # This prevents Tcl_AsyncDelete crash if callback executes after window destruction
        if not self.is_window_alive():
            return  # Window destroyed, don't update
        
        try:
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

            # Update progress bar (smooth fill animation)
            progress_canvas.delete("all")
            
            # Get actual canvas width (more reliable than calculating)
            try:
                progress_canvas.update_idletasks()
                canvas_width = progress_canvas.winfo_width()
                if canvas_width <= 1:
                    # Canvas not yet rendered, calculate from window width
                    if self._window:
                        self._window.update_idletasks()
                        window_width = self._window.winfo_width()
                        if window_width > 1:
                            canvas_width = window_width - (STANDARD_PADX * 2)
                        else:
                            canvas_width = 432  # Default fallback
                    else:
                        canvas_width = 432  # Default fallback
            except:
                # Fallback calculation
                canvas_width = 432
            bar_width = canvas_width * progress_percent
            progress_canvas.create_rectangle(
                0,
                0,
                bar_width,
                28,  # Match height
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
        except (tk.TclError, RuntimeError):
            # Window/widgets destroyed during update
            return

    def _stop_timer(self):
        """Stop the countdown timer"""
        self._timer_stop_event.set()
        if self._timer_thread and self._timer_thread.is_alive():
            # Wait for thread to exit (with timeout)
            self._timer_thread.join(timeout=2)
            # If thread is still alive after timeout, log warning
            if self._timer_thread.is_alive():
                self._log("[USER_POPUP] WARNING: Timer thread did not exit within timeout")

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

        # Get available width for text wrapping
        available_width = self._get_available_width()

        # Success message - Bold, green for success state
        message = tk.Label(
            self._content_frame,
            text="Input control enabled",
            bg=COLOR_BG_WHITE,
            fg=COLOR_GREEN,  # Green for success
            font=FONT_HEADING,  # Use heading font
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        # Details - Regular weight, medium gray
        details = tk.Label(
            self._content_frame,
            text="You now have full control of the remote desktop.\n\n" "You may proceed with the session.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,  # Medium gray for secondary text
            font=FONT_SECONDARY,
            justify=tk.LEFT,
            anchor="w",
            wraplength=available_width,
        )
        details.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

        # Continue button
        def on_continue():
            """Close popup"""
            self.close()

        continue_btn = _create_button_with_hover(
            self._content_frame,
            "Continue",
            on_continue,
            COLOR_GREEN,
            COLOR_GREEN_HOVER,
        )
        continue_btn.pack(fill=tk.X, pady=(0, 0))  # Full width button

    def _render_failure_state(self):
        """
        Render the failure screen if scammer rejects.

        FAILURE OPTIONS:
        - Retry: Send another reverse connection request
        - Disconnect: Kill AnyDesk connection entirely
        """
        # Stop timer
        self._stop_timer()

        # Get available width for text wrapping
        available_width = self._get_available_width()

        # Failure message - Bold, orange for failure state
        message = tk.Label(
            self._content_frame,
            text="Activation request declined",
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE,
            font=FONT_HEADING,  # Use heading font
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        # Details - Regular weight, medium gray
        details = tk.Label(
            self._content_frame,
            text=f"The remote client declined the input control request.\n\n"
            f"Remote input control cannot be enabled without\nactivation approval.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,  # Medium gray for secondary text
            font=FONT_SECONDARY,
            justify=tk.LEFT,
            anchor="w",
            wraplength=available_width,
        )
        details.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

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

        retry_btn = _create_button_with_hover(
            button_frame,
            "Retry",
            on_retry,
            COLOR_BLUE,
            COLOR_BLUE_HOVER,
        )
        retry_btn.pack(side=tk.LEFT, padx=(0, ELEMENT_SPACING))

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

        disconnect_btn = _create_button_with_hover(
            button_frame,
            "Disconnect",
            on_disconnect,
            COLOR_ORANGE,
            COLOR_ORANGE_HOVER,
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
        # Get available width for text wrapping
        available_width = self._get_available_width()

        # Timeout message - Bold, orange for timeout state
        message = tk.Label(
            self._content_frame,
            text="Activation request expired",
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE,  # Orange for timeout/warning
            font=FONT_HEADING,  # Use heading font
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        # Details - Regular weight, medium gray
        details = tk.Label(
            self._content_frame,
            text="The activation request timed out.\n\n" "Session will remain in view-only mode.",
            bg=COLOR_BG_WHITE,
            fg=COLOR_TEXT_SECONDARY,  # Medium gray for secondary text
            font=FONT_SECONDARY,
            justify=tk.LEFT,
            anchor="w",
            wraplength=available_width,
        )
        details.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

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

        retry_btn = _create_button_with_hover(
            button_frame,
            "Retry",
            on_retry,
            COLOR_BLUE,
            COLOR_BLUE_HOVER,
        )
        retry_btn.pack(side=tk.LEFT, padx=(0, ELEMENT_SPACING))

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

        disconnect_btn = _create_button_with_hover(
            button_frame,
            "Disconnect",
            on_disconnect,
            COLOR_ORANGE,
            COLOR_ORANGE_HOVER,
        )
        disconnect_btn.pack(side=tk.LEFT)

    def transition_to_success(self):
        """
        Transition to success state (called from main thread).
        Thread-safe method for external state changes.
        """
        if self.is_window_alive() and not self._closed:
            try:
                self._window.after(0, self._transition_to_state, PopupState.SUCCESS)
            except (tk.TclError, RuntimeError):
                pass

    def transition_to_failure(self):
        """
        Transition to failure state (called from main thread).
        Thread-safe method for external state changes.
        """
        if self.is_window_alive() and not self._closed:
            try:
                self._window.after(0, self._transition_to_state, PopupState.FAILURE)
            except (tk.TclError, RuntimeError):
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
