"""
Process Decision Popup
Shows Tkinter dialogs for whitelist/blacklist decisions on unknown processes.
"""

import threading
import tkinter as tk
from tkinter import messagebox


def show_process_decision_popup(process_name, exe_path, callback, log_func=None):
    """
    Show a Tkinter dialog asking user to whitelist or blacklist a process.

    Args:
        process_name: Name of the unknown process
        exe_path: Path to the executable
        callback: Function to call with decision ("whitelist" or "blacklist")
        log_func: Optional logging function
    """
    log = log_func if log_func else lambda msg: None

    def show_dialog():
        try:
            # Create root window
            root = tk.Tk()
            root.withdraw()  # Hide the main window

            # Message for the user
            message = (
                f"Unknown process detected:\n\n"
                f"Process: {process_name}\n"
                f"Path: {exe_path}\n\n"
                f"Input is currently BLOCKED.\n\n"
                f"Do you want to WHITELIST this process?\n"
                f"(Click 'No' to BLACKLIST it)"
            )

            # Show Yes/No dialog
            # Yes = Whitelist, No = Blacklist
            result = messagebox.askyesno("Blackhole - Unknown Process", message, icon=messagebox.WARNING)

            root.destroy()

            # Call callback with decision
            decision = "whitelist" if result else "blacklist"
            log(f"[POPUP] User decided to {decision} {process_name}")

            if callback:
                callback(decision)

        except Exception as e:
            log(f"[POPUP] Error showing dialog: {e}")

    # Run in background thread to not block main loop
    popup_thread = threading.Thread(target=show_dialog, daemon=True, name="DecisionPopup")
    popup_thread.start()


def show_hash_mismatch_popup(process_name, exe_path, is_signed, callback, log_func=None):
    """
    Show a dialog that a whitelisted process has a changed hash.

    Args:
        process_name: Name of the process
        exe_path: Path to the executable
        is_signed: Whether the process is Microsoft-signed
        callback: Function to call with decision ("whitelist" or "blacklist")
        log_func: Optional logging function
    """
    log = log_func if log_func else lambda msg: None

    def show_dialog():
        try:
            root = tk.Tk()
            root.withdraw()

            if is_signed:
                # Microsoft-signed process - this should have been auto-updated
                message = (
                    f"SECURITY ALERT!\n\n"
                    f"Microsoft-signed process failed verification:\n"
                    f"{process_name}\n\n"
                    f"Path: {exe_path}\n\n"
                    f"This process has been AUTOMATICALLY BLACKLISTED.\n"
                    f"Possible imposter or corrupted file."
                )
                title = "Blackhole - Security Alert"
                messagebox.showerror(title, message)
            else:
                # Unsigned process - requires user decision
                message = (
                    f"Hash changed for whitelisted process:\n\n"
                    f"Process: {process_name}\n"
                    f"Path: {exe_path}\n\n"
                    f"Input is currently BLOCKED.\n\n"
                    f"Do you want to RE-WHITELIST this process?\n"
                    f"(Click 'No' to BLACKLIST it)"
                )
                title = "Blackhole - Hash Mismatch"
                result = messagebox.askyesno(title, message, icon=messagebox.WARNING)

                # Call callback with decision
                decision = "whitelist" if result else "blacklist"
                log(f"[POPUP] User decided to {decision} {process_name}")

                if callback:
                    callback(decision)

            root.destroy()
            log(f"[POPUP] Showed hash mismatch popup for {process_name}")

        except Exception as e:
            log(f"[POPUP] Error showing dialog: {e}")

    # Run in background thread
    popup_thread = threading.Thread(target=show_dialog, daemon=True, name="HashMismatchPopup")
    popup_thread.start()


def show_imposter_alert(process_name, exe_path, log_func=None):
    """
    Show a critical alert that an imposter process was detected.

    Args:
        process_name: Name of the imposter process
        exe_path: Path to the executable
        log_func: Optional logging function
    """
    log = log_func if log_func else lambda msg: None

    def show_dialog():
        try:
            root = tk.Tk()
            root.withdraw()

            message = (
                f"CRITICAL SECURITY ALERT!\n\n"
                f"IMPOSTER DETECTED:\n"
                f"{process_name}\n\n"
                f"Path: {exe_path}\n\n"
                f"A process is masquerading as a Microsoft application.\n"
                f"This process has been BLOCKED and BLACKLISTED.\n\n"
                f"Possible malware or compromised system!"
            )

            messagebox.showerror("Blackhole - IMPOSTER DETECTED", message)

            root.destroy()
            log(f"[POPUP] Showed imposter alert for {process_name}")

        except Exception as e:
            log(f"[POPUP] Error showing dialog: {e}")

    # Run in background thread
    popup_thread = threading.Thread(target=show_dialog, daemon=True, name="ImposterAlert")
    popup_thread.start()
