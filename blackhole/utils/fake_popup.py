"""
Fake AnyDesk Popup - Tkinter window mimicking AnyDesk notifications
Used to trick scammers into accepting reverse connections
"""

import threading
import customtkinter as ctk
import tkinter as tk  # For TclError


class FakePopup:
    """
    Creates a fake AnyDesk notification window.
    Simple styling for Phase 1 - advanced styling in future versions.
    """

    def __init__(self, message, timeout=30, log_func=None):
        """
        Initialize the fake popup.

        Args:
            message: Message to display
            timeout: Auto-dismiss timeout in seconds (default: 30)
            log_func: Optional logging function
        """
        self._message = message
        self._timeout = timeout
        self._log = log_func if log_func else lambda msg: None
        self._window = None
        self._closed = False
        self._thread = None

    def show(self):
        """
        Show the popup window.
        Non-blocking: Runs in separate thread.
        """
        if self._window is not None:
            self._log("[FAKE_POPUP] Popup already shown")
            return

        self._log("[FAKE_POPUP] Showing fake AnyDesk popup...")

        # Run Tkinter in separate thread
        self._thread = threading.Thread(target=self._show_window, daemon=True, name="FakePopup")
        self._thread.start()

    def _show_window(self):
        """Create and show the Tkinter window"""
        try:
            # Create root window
            self._window = ctk.CTk()
            self._window.title("AnyDesk")

            # Window size
            window_width = 450
            window_height = 180

            # Center on screen
            screen_width = self._window.winfo_screenwidth()
            screen_height = self._window.winfo_screenheight()
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            self._window.geometry(f"{window_width}x{window_height}+{x}+{y}")

            # Window properties
            self._window.attributes("-topmost", True)  # Always on top
            self._window.resizable(False, False)

            # Icon (optional - use default for now)
            # TODO: Add AnyDesk icon in future phase

            # Configure background
            self._window.configure(fg_color="#f5f5f5")

            # Title bar with AnyDesk branding
            title_frame = ctk.CTkFrame(self._window, fg_color="#d51317", height=40, corner_radius=0, border_width=0)
            title_frame.pack(fill="x", side="top")
            title_frame.pack_propagate(False)

            title_label = ctk.CTkLabel(
                title_frame,
                text="AnyDesk",
                fg_color="#d51317",
                text_color="white",
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w",
                padx=15,
            )
            title_label.pack(fill="both", expand=True)

            # Message frame
            message_frame = ctk.CTkFrame(self._window, fg_color="#f5f5f5", corner_radius=0, border_width=0)
            message_frame.pack(fill="both", expand=True, padx=20, pady=20)

            # Hourglass icon (simple text representation)
            icon_label = ctk.CTkLabel(message_frame, text="⏳", fg_color="transparent", font=ctk.CTkFont(size=32))
            icon_label.pack(pady=(0, 10))

            # Message text
            message_label = ctk.CTkLabel(
                message_frame,
                text=self._message,
                fg_color="transparent",
                text_color="#333333",
                font=ctk.CTkFont(size=9),
                justify="center",
                wraplength=400,
            )
            message_label.pack()

            # Close button handler
            def on_close():
                if not self._closed:
                    self._closed = True
                    self._log("[FAKE_POPUP] Popup closed by user")
                    self._window.quit()
                    self._window.destroy()

            self._window.protocol("WM_DELETE_WINDOW", on_close)

            # Auto-dismiss after timeout
            if self._timeout > 0:
                self._window.after(self._timeout * 1000, self.close)

            # Run main loop
            self._window.mainloop()

        except Exception as e:
            self._log(f"[FAKE_POPUP] Error showing popup: {e}")

    def close(self):
        """Close the popup window"""
        if self._closed:
            return

        self._closed = True
        self._log("[FAKE_POPUP] Closing popup...")

        if self._window:
            try:
                self._window.quit()
                self._window.destroy()
            except (tk.TclError, RuntimeError):
                # Window already destroyed
                pass

    def is_closed(self):
        """Check if popup is closed"""
        return self._closed


def create_fake_anydesk_popup(log_func=None):
    """
    Factory function to create a fake AnyDesk popup with standard message.

    Args:
        log_func: Optional logging function

    Returns:
        FakePopup: Configured popup instance
    """
    message = (
        "Waiting for remote authorization...\n\n"
        "Remote input is disabled until the client\n"
        "accepts the enhanced security prompt.\n\n"
        "Please wait..."
    )

    return FakePopup(message, timeout=0, log_func=log_func)  # timeout=0 means no auto-dismiss
