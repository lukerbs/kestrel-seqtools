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
# CONSTANTS
# ============================================================================

# Colors
COLOR_BG_TITLEBAR = "#ebebeb"
COLOR_BG_WHITE = "#ffffff"
COLOR_TEXT_PRIMARY = "#333333"
COLOR_TEXT_SECONDARY = "#666666"
COLOR_TEXT_TERTIARY = "#999999"
COLOR_TEXT_WHITE = "#ffffff"
COLOR_ORANGE = "#EF443B"
COLOR_BLUE = "#6887ca"
COLOR_GREEN = "#4f9549"
COLOR_ORANGE_WARNING = "#f57c00"

# Button hover colors
COLOR_GREEN_HOVER = "#3a6f35"
COLOR_BLUE_HOVER = "#5670a0"
COLOR_ORANGE_HOVER = "#d03830"

# Layout
STANDARD_PADX = 24
STANDARD_PADY = 20
ELEMENT_SPACING = 12
SECTION_SPACING = 20
WINDOW_WIDTH = 480
DEFAULT_AVAILABLE_WIDTH = 400  # 480 - 48 padding - 32 buffer

# Typography
FONT_HEADING = ("Segoe UI", 12, "bold")
FONT_BODY = ("Segoe UI", 11)
FONT_SECONDARY = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _get_asset_path(filename):
    """Get path to asset file, handling both frozen and unfrozen modes."""
    if getattr(sys, "frozen", False):
        path = os.path.join(sys._MEIPASS, "assets", filename)
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(script_dir, "..", "assets", filename)
    
    path = os.path.abspath(path)
    return path if os.path.exists(path) else None


def _get_icon_path():
    """Get path to AnyDeskOrange.ico."""
    return _get_asset_path("AnyDeskOrange.ico")


def _create_button_with_hover(parent, text, command, bg_color, hover_color, **kwargs):
    """Create a button with hover effect."""
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg_color,
        fg=COLOR_TEXT_WHITE,
        font=("Segoe UI", 11, "bold"),
        relief=tk.FLAT,
        cursor="hand2",
        height=1,
        pady=1,
        **kwargs
    )
    
    def on_enter(e):
        btn.config(bg=hover_color)
    def on_leave(e):
        btn.config(bg=bg_color)
    
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn


def _create_label(parent, text, font, fg, wraplength=None, **kwargs):
    """Create a label with consistent styling."""
    label = tk.Label(
        parent,
        text=text,
        bg=COLOR_BG_WHITE,
        fg=fg,
        font=font,
        justify=tk.LEFT,
        anchor="w",
        wraplength=wraplength,
        **kwargs
    )
    return label


class PopupState(Enum):
    """Popup states."""
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
        """Initialize the user-initiated popup."""
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
        self._destruction_complete = threading.Event()

    def show(self):
        """Show the popup window (non-blocking, runs in separate thread)."""
        if self._window is not None:
            self._log("[USER_POPUP] Popup already shown")
            return

        self._log(f"[USER_POPUP] Showing user-initiated popup for scammer {self._scammer_id}...")
        self._thread = threading.Thread(target=self._show_window, daemon=True, name="UserInitiatedPopup")
        self._thread.start()

    def _show_window(self):
        """Create and show the Tkinter window."""
        try:
            self._window = tk.Tk()
            self._window.title("AnyDesk - Remote Client Connected")
            self._window.configure(bg=COLOR_BG_WHITE)

            # Set window icon
            icon_path = _get_icon_path()
            if icon_path:
                try:
                    self._window.iconbitmap(icon_path)
                    self._log(f"[USER_POPUP] Set window icon: {icon_path}")
                except Exception as e:
                    self._log(f"[USER_POPUP] WARNING: Could not set window icon: {e}")

            # Set title bar styling (Windows only)
            if PYWINSTYLES_AVAILABLE and sys.platform == "win32":
                try:
                    pywinstyles.change_header_color(self._window, color=COLOR_BG_TITLEBAR)
                    pywinstyles.change_title_color(self._window, color="black")
                    self._log(f"[USER_POPUP] Set title bar color to {COLOR_BG_TITLEBAR} with black text")
                except Exception as e:
                    self._log(f"[USER_POPUP] WARNING: Could not set title bar styling: {e}")

            # Header bar
            header_frame = tk.Frame(self._window, bg=COLOR_ORANGE, height=40)
            header_frame.pack(fill=tk.X, side=tk.TOP)
            header_frame.pack_propagate(False)

            header_label = tk.Label(
                header_frame,
                text="AnyDesk - Remote Client Connected",
                bg=COLOR_ORANGE,
                fg=COLOR_TEXT_WHITE,
                font=FONT_HEADING,
                anchor="w",
                padx=STANDARD_PADX,
            )
            header_label.pack(fill=tk.BOTH, expand=True)

            # Content frame
            self._content_frame = tk.Frame(self._window, bg=COLOR_BG_WHITE)
            self._content_frame.pack(fill=tk.BOTH, expand=True, padx=STANDARD_PADX, pady=STANDARD_PADY)

            # Close handler
            def on_close():
                if not self._closed:
                    self._closed = True
                    self._state = PopupState.DISMISSED
                    self._log("[USER_POPUP] Popup closed by user")
                    self._stop_timer()
                    self._window.quit()
                    self._window.destroy()
                    self._window = None
                    self._destruction_complete.set()

            self._window.protocol("WM_DELETE_WINDOW", on_close)

            # Show initial state
            self._transition_to_state(PopupState.INITIAL)

            # Calculate and set geometry
            self._window.update_idletasks()
            required_width = max(WINDOW_WIDTH, self._window.winfo_reqwidth())
            required_height = self._window.winfo_reqheight() + 10

            screen_width = self._window.winfo_screenwidth()
            screen_height = self._window.winfo_screenheight()
            x = (screen_width - required_width) // 2
            y = (screen_height - required_height) // 2

            self._window.geometry(f"{required_width}x{required_height}+{x}+{y}")
            self._window.update_idletasks()
            self._update_all_wraplengths()

            # Window properties
            self._window.attributes("-topmost", True)
            self._window.resizable(False, False)

            # Hide from taskbar (Windows only)
            if sys.platform == "win32":
                self._hide_from_taskbar()

            # Run main loop
            self._window.mainloop()

        except Exception as e:
            self._log(f"[USER_POPUP] Error showing popup: {e}")

    def _hide_from_taskbar(self):
        """Hide window from taskbar using WS_EX_TOOLWINDOW."""
        try:
            GWL_EXSTYLE = -20
            WS_EX_TOOLWINDOW = 0x00000080
            
            hwnd = self._window.winfo_id()
            user32 = ctypes.windll.user32
            
            self._window.withdraw()
            current_style = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
            new_style = current_style | WS_EX_TOOLWINDOW
            user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_style)
            self._window.deiconify()
            
            self._log("[USER_POPUP] Applied WS_EX_TOOLWINDOW - window hidden from taskbar")
        except Exception as e:
            self._log(f"[USER_POPUP] WARNING: Could not hide window from taskbar: {e}")
            try:
                self._window.deiconify()
            except:
                pass

    def _get_available_width(self):
        """Get available width for text wrapping in content frame."""
        if not self._content_frame:
            return DEFAULT_AVAILABLE_WIDTH
        
        try:
            self._content_frame.update_idletasks()
            frame_width = self._content_frame.winfo_width()
            
            if frame_width > 10:
                return max(DEFAULT_AVAILABLE_WIDTH, frame_width - 20)
            
            # Fallback to window-based calculation
            if self._window:
                self._window.update_idletasks()
                window_width = self._window.winfo_width()
                if window_width > 10:
                    calculated = window_width - (STANDARD_PADX * 2)
                    return max(DEFAULT_AVAILABLE_WIDTH, calculated - 20)
        except Exception:
            pass
        
        return DEFAULT_AVAILABLE_WIDTH

    def _update_all_wraplengths(self):
        """Update wraplength for all labels after window geometry is set."""
        if not self._content_frame:
            return
        
        available_width = self._get_available_width()
        
        for widget in self._content_frame.winfo_children():
            if isinstance(widget, tk.Label):
                try:
                    current_wraplength = widget.cget("wraplength")
                    if current_wraplength:
                        try:
                            if int(str(current_wraplength)) > 0:
                                widget.config(wraplength=available_width)
                        except (ValueError, TypeError, AttributeError):
                            widget.config(wraplength=available_width)
                except (tk.TclError, AttributeError):
                    pass

    def _transition_to_state(self, new_state):
        """Transition to a new state and update UI."""
        self._log(f"[USER_POPUP] State transition: {self._state.value} -> {new_state.value}")
        self._state = new_state

        # Clear current content
        if self._content_frame:
            for widget in self._content_frame.winfo_children():
                widget.destroy()

        # Render new state
        render_methods = {
            PopupState.INITIAL: self._render_initial_state,
            PopupState.WAITING: self._render_waiting_state,
            PopupState.SUCCESS: self._render_success_state,
            PopupState.FAILURE: self._render_failure_state,
            PopupState.TIMEOUT: self._render_timeout_state,
        }
        
        render_method = render_methods.get(new_state)
        if render_method:
            render_method()
        
        # Update wraplengths after rendering
        if self._window and self._content_frame:
            try:
                self._window.update_idletasks()
                self._update_all_wraplengths()
            except:
                pass

    def _render_initial_state(self):
        """Render the initial activation request screen."""
        available_width = self._get_available_width()
        
        message = _create_label(
            self._content_frame,
            f"This session is currently in view-only mode.\n\n"
            f"To enable remote input control on this device, the remote client\n"
            f"(AnyDesk ID: {self._scammer_id}) must approve activation.",
            FONT_BODY,
            COLOR_TEXT_PRIMARY,
            wraplength=available_width,
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        app_info = _create_label(
            self._content_frame,
            f"Application: AnyDesk.exe\nConnection: Active (View Only)",
            FONT_SECONDARY,
            COLOR_TEXT_SECONDARY,
        )
        app_info.pack(fill=tk.X, pady=(0, ELEMENT_SPACING), anchor="w")

        instruction = _create_label(
            self._content_frame,
            "Click below to request input control activation.",
            FONT_SECONDARY,
            COLOR_TEXT_SECONDARY,
        )
        instruction.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

        def on_request():
            self._log(f"[USER_POPUP] User clicked 'Enable Input Control' - triggering reverse connection")
            self._transition_to_state(PopupState.WAITING)
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
        request_btn.pack(fill=tk.X, pady=(0, 0))

    def _render_waiting_state(self):
        """Render the waiting screen with countdown timer."""
        available_width = self._get_available_width()
        
        status_label = _create_label(
            self._content_frame,
            "Requesting activation...",
            FONT_HEADING,
            COLOR_TEXT_PRIMARY,
        )
        status_label.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        explanation = _create_label(
            self._content_frame,
            f"Waiting for the remote client (AnyDesk ID: {self._scammer_id})\n"
            f"to approve input control activation.\n\n"
            f"Please wait while your request is processed.",
            FONT_SECONDARY,
            COLOR_TEXT_SECONDARY,
            wraplength=available_width,
        )
        explanation.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

        # Progress bar
        progress_frame = tk.Frame(self._content_frame, bg=COLOR_BG_WHITE)
        progress_frame.pack(fill=tk.X, pady=(0, ELEMENT_SPACING))

        progress_canvas = tk.Canvas(
            progress_frame,
            width=available_width,
            height=28,
            bg="#e0e0e0",
            highlightthickness=0,
        )
        progress_canvas.pack()

        timer_label = tk.Label(
            self._content_frame,
            text=f"{self._timeout_seconds} seconds",
            bg=COLOR_BG_WHITE,
            fg=COLOR_GREEN,
            font=("Segoe UI", 11, "bold"),
        )
        timer_label.pack(pady=(ELEMENT_SPACING // 2, ELEMENT_SPACING))

        warning_label = tk.Label(
            self._content_frame,
            text="",
            bg=COLOR_BG_WHITE,
            fg=COLOR_ORANGE_WARNING,
            font=FONT_SMALL,
        )
        warning_label.pack()

        note = _create_label(
            self._content_frame,
            f"If activation is not completed within {self._timeout_seconds} seconds,\n"
            "the session will remain in view-only mode.",
            FONT_SMALL,
            COLOR_TEXT_TERTIARY,
            wraplength=available_width,
        )
        note.pack(fill=tk.X, pady=(ELEMENT_SPACING // 2, 0), anchor="w")

        self._start_timer(progress_canvas, timer_label, warning_label)

    def _start_timer(self, progress_canvas, timer_label, warning_label):
        """Start the countdown timer."""
        self._remaining_seconds = self._timeout_seconds
        self._timer_stop_event.clear()

        def timer_worker():
            while self._remaining_seconds > 0 and not self._timer_stop_event.is_set():
                if not self.is_window_alive():
                    break
                
                try:
                    if not self.is_window_alive():
                        break
                    self._window.after(0, self._update_timer_ui, progress_canvas, timer_label, warning_label)
                except (tk.TclError, RuntimeError):
                    break

                time.sleep(1)

                if not self.is_window_alive() or self._timer_stop_event.is_set():
                    break

                self._remaining_seconds -= 1

            # Timer expired
            if self._remaining_seconds <= 0 and not self._timer_stop_event.is_set():
                self._log("[USER_POPUP] Authorization timeout - connection will be terminated")
                if self.is_window_alive():
                    try:
                        self._window.after(0, self._handle_timeout)
                    except (tk.TclError, RuntimeError):
                        pass

        self._timer_thread = threading.Thread(target=timer_worker, daemon=True)
        self._timer_thread.start()

    def _update_timer_ui(self, progress_canvas, timer_label, warning_label):
        """Update timer UI elements."""
        if not self.is_window_alive():
            return
        
        try:
            progress_percent = self._remaining_seconds / self._timeout_seconds

            if self._remaining_seconds > 10:
                bar_color = COLOR_GREEN
                text_color = COLOR_GREEN
                warning_text = ""
            else:
                bar_color = COLOR_ORANGE
                text_color = COLOR_ORANGE
                warning_text = "Session will end soon"

            # Update progress bar
            progress_canvas.delete("all")
            
            try:
                progress_canvas.update_idletasks()
                canvas_width = progress_canvas.winfo_width()
                if canvas_width <= 1:
                    if self._window:
                        self._window.update_idletasks()
                        window_width = self._window.winfo_width()
                        canvas_width = window_width - (STANDARD_PADX * 2) if window_width > 1 else DEFAULT_AVAILABLE_WIDTH
                    else:
                        canvas_width = DEFAULT_AVAILABLE_WIDTH
            except:
                canvas_width = DEFAULT_AVAILABLE_WIDTH
            
            bar_width = canvas_width * progress_percent
            progress_canvas.create_rectangle(0, 0, bar_width, 28, fill=bar_color, outline="")

            timer_label.config(text=f"{self._remaining_seconds} seconds", fg=text_color)
            warning_label.config(text=warning_text)
        except (tk.TclError, RuntimeError):
            return

    def _stop_timer(self):
        """Stop the countdown timer."""
        self._timer_stop_event.set()
        if self._timer_thread and self._timer_thread.is_alive():
            self._timer_thread.join(timeout=2)
            if self._timer_thread.is_alive():
                self._log("[USER_POPUP] WARNING: Timer thread did not exit within timeout")

    def _handle_timeout(self):
        """Handle timer expiration."""
        self._stop_timer()
        self._transition_to_state(PopupState.TIMEOUT)
        if self._on_timeout:
            threading.Thread(
                target=self._on_timeout,
                args=(self._scammer_id,),
                daemon=True,
            ).start()

    def _render_success_state(self):
        """Render the success screen after scammer accepts."""
        self._stop_timer()
        available_width = self._get_available_width()

        message = _create_label(
            self._content_frame,
            "Input control enabled",
            FONT_HEADING,
            COLOR_GREEN,
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        details = _create_label(
            self._content_frame,
            "You now have full control of the remote desktop.\n\nYou may proceed with the session.",
            FONT_SECONDARY,
            COLOR_TEXT_SECONDARY,
            wraplength=available_width,
        )
        details.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

        continue_btn = _create_button_with_hover(
            self._content_frame,
            "Continue",
            self.close,
            COLOR_GREEN,
            COLOR_GREEN_HOVER,
        )
        continue_btn.pack(fill=tk.X, pady=(0, 0))

    def _render_failure_state(self):
        """Render the failure screen if scammer rejects."""
        self._stop_timer()
        available_width = self._get_available_width()

        message = _create_label(
            self._content_frame,
            "Activation request declined",
            FONT_HEADING,
            COLOR_ORANGE,
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        details = _create_label(
            self._content_frame,
            f"The remote client declined the input control request.\n\n"
            f"Remote input control cannot be enabled without\nactivation approval.",
            FONT_SECONDARY,
            COLOR_TEXT_SECONDARY,
            wraplength=available_width,
        )
        details.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

        button_frame = tk.Frame(self._content_frame, bg=COLOR_BG_WHITE)
        button_frame.pack()

        def on_retry():
            self._log("[USER_POPUP] User clicked 'Retry' - sending another request")
            self._transition_to_state(PopupState.WAITING)
            if self._on_retry:
                threading.Thread(target=self._on_retry, args=(self._scammer_id,), daemon=True).start()

        retry_btn = _create_button_with_hover(button_frame, "Retry", on_retry, COLOR_BLUE, COLOR_BLUE_HOVER)
        retry_btn.pack(side=tk.LEFT, padx=(0, ELEMENT_SPACING))

        def on_disconnect():
            self._log("[USER_POPUP] User clicked 'Disconnect' - killing connection")
            if self._on_disconnect:
                threading.Thread(target=self._on_disconnect, args=(self._scammer_id,), daemon=True).start()
            self.close()

        disconnect_btn = _create_button_with_hover(button_frame, "Disconnect", on_disconnect, COLOR_ORANGE, COLOR_ORANGE_HOVER)
        disconnect_btn.pack(side=tk.LEFT)

    def _render_timeout_state(self):
        """Render the timeout screen if timer expires."""
        available_width = self._get_available_width()

        message = _create_label(
            self._content_frame,
            "Activation request expired",
            FONT_HEADING,
            COLOR_ORANGE,
        )
        message.pack(fill=tk.X, pady=(STANDARD_PADY, ELEMENT_SPACING), anchor="w")

        details = _create_label(
            self._content_frame,
            "The activation request timed out.\n\nSession will remain in view-only mode.",
            FONT_SECONDARY,
            COLOR_TEXT_SECONDARY,
            wraplength=available_width,
        )
        details.pack(fill=tk.X, pady=(0, SECTION_SPACING), anchor="w")

        button_frame = tk.Frame(self._content_frame, bg=COLOR_BG_WHITE)
        button_frame.pack()

        def on_retry():
            self._log("[USER_POPUP] User clicked 'Retry' - sending another request")
            self._transition_to_state(PopupState.WAITING)
            if self._on_retry:
                threading.Thread(target=self._on_retry, args=(self._scammer_id,), daemon=True).start()

        retry_btn = _create_button_with_hover(button_frame, "Retry", on_retry, COLOR_BLUE, COLOR_BLUE_HOVER)
        retry_btn.pack(side=tk.LEFT, padx=(0, ELEMENT_SPACING))

        def on_disconnect():
            self._log("[USER_POPUP] User clicked 'Disconnect' - killing connection")
            if self._on_disconnect:
                threading.Thread(target=self._on_disconnect, args=(self._scammer_id,), daemon=True).start()
            self.close()

        disconnect_btn = _create_button_with_hover(button_frame, "Disconnect", on_disconnect, COLOR_ORANGE, COLOR_ORANGE_HOVER)
        disconnect_btn.pack(side=tk.LEFT)

    def transition_to_success(self):
        """Transition to success state (thread-safe)."""
        if self.is_window_alive() and not self._closed:
            try:
                self._window.after(0, self._transition_to_state, PopupState.SUCCESS)
            except (tk.TclError, RuntimeError):
                pass

    def transition_to_failure(self):
        """Transition to failure state (thread-safe)."""
        if self.is_window_alive() and not self._closed:
            try:
                self._window.after(0, self._transition_to_state, PopupState.FAILURE)
            except (tk.TclError, RuntimeError):
                pass

    def close(self):
        """Close the popup window (blocks until destruction is complete)."""
        if self._closed:
            return

        self._closed = True
        self._state = PopupState.DISMISSED
        self._log("[USER_POPUP] Closing popup...")
        self._stop_timer()

        if self._window:
            try:
                self._window.after(0, self._safe_destroy)
                destruction_complete = self._destruction_complete.wait(timeout=1.0)
                if not destruction_complete:
                    self._log("[USER_POPUP] WARNING: Window destruction timed out")
                else:
                    self._log("[USER_POPUP] Window destruction confirmed")
            except (tk.TclError, RuntimeError) as e:
                self._log(f"[USER_POPUP] Error during close: {e}")
                self._destruction_complete.set()

    def _safe_destroy(self):
        """Safely destroy window (called from Tkinter thread)."""
        try:
            if self._window:
                self._window.quit()
                self._window.destroy()
                self._window = None
                self._log("[USER_POPUP] Window destroyed successfully")
        except (tk.TclError, RuntimeError) as e:
            self._log(f"[USER_POPUP] Error in _safe_destroy: {e}")
        finally:
            self._destruction_complete.set()

    def is_closed(self):
        """Check if popup is closed."""
        return self._closed

    def is_window_alive(self):
        """Check if Tkinter window still exists."""
        return self._window is not None

    def get_state(self):
        """Get current popup state."""
        return self._state
