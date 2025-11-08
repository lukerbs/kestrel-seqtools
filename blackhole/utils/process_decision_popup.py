"""
Process Decision Popup
Shows Tkinter dialogs for whitelist/blacklist decisions on unknown processes.
Uses a dedicated GUI thread with a queue to handle multiple popup requests safely.
"""

import threading
import tkinter as tk
from tkinter import messagebox
import queue
import time


# Global queue and thread for handling popups
_popup_queue = queue.Queue()
_popup_thread = None
_popup_thread_lock = threading.Lock()


def _popup_worker():
    """
    Dedicated thread that processes popup requests from the queue.
    Creates ONE Tkinter root and processes all popups sequentially.
    """
    while True:
        try:
            # Get next popup request (blocking)
            popup_type, args = _popup_queue.get(timeout=1)

            if popup_type == "stop":
                break

            # Create a new root for each dialog
            root = tk.Tk()
            root.withdraw()

            try:
                if popup_type == "decision":
                    process_name, exe_path, callback, log_func = args
                    _show_decision_dialog(root, process_name, exe_path, callback, log_func)
                elif popup_type == "hash_mismatch":
                    process_name, exe_path, is_signed, callback, log_func = args
                    _show_hash_mismatch_dialog(root, process_name, exe_path, is_signed, callback, log_func)
                elif popup_type == "imposter":
                    process_name, exe_path, log_func = args
                    _show_imposter_dialog(root, process_name, exe_path, log_func)
            finally:
                root.destroy()

            _popup_queue.task_done()

            # Small delay to prevent overwhelming the user
            time.sleep(0.1)

        except queue.Empty:
            continue
        except Exception as e:
            print(f"[POPUP] Worker error: {e}")


def _ensure_popup_thread():
    """Ensure the popup worker thread is running."""
    global _popup_thread
    with _popup_thread_lock:
        if _popup_thread is None or not _popup_thread.is_alive():
            _popup_thread = threading.Thread(target=_popup_worker, daemon=True, name="PopupWorker")
            _popup_thread.start()


def _show_decision_dialog(root, process_name, exe_path, callback, log_func):
    """Show the decision dialog (called from popup worker thread)."""
    log = log_func if log_func else lambda msg, **kwargs: None

    message = (
        f"Unknown process detected:\n\n"
        f"Process: {process_name}\n"
        f"Path: {exe_path}\n\n"
        f"Input is currently BLOCKED.\n\n"
        f"Do you want to WHITELIST this process?\n"
        f"(Click 'No' to BLACKLIST it)"
    )

    result = messagebox.askyesno("Blackhole - Unknown Process", message, icon=messagebox.WARNING)

    decision = "whitelist" if result else "blacklist"
    log(f"[POPUP] User decided to {decision} {process_name}")

    if callback:
        callback(decision)


def show_process_decision_popup(process_name, exe_path, callback, log_func=None):
    """
    Show a Tkinter dialog asking user to whitelist or blacklist a process.

    Args:
        process_name: Name of the unknown process
        exe_path: Path to the executable
        callback: Function to call with decision ("whitelist" or "blacklist")
        log_func: Optional logging function
    """
    _ensure_popup_thread()
    _popup_queue.put(("decision", (process_name, exe_path, callback, log_func)))


def _show_hash_mismatch_dialog(root, process_name, exe_path, is_signed, callback, log_func):
    """Show the hash mismatch dialog (called from popup worker thread)."""
    log = log_func if log_func else lambda msg, **kwargs: None

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

    log(f"[POPUP] Showed hash mismatch popup for {process_name}")


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
    _ensure_popup_thread()
    _popup_queue.put(("hash_mismatch", (process_name, exe_path, is_signed, callback, log_func)))


def _show_imposter_dialog(root, process_name, exe_path, log_func):
    """Show the imposter alert dialog (called from popup worker thread)."""
    log = log_func if log_func else lambda msg, **kwargs: None

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
    log(f"[POPUP] Showed imposter alert for {process_name}")


def show_imposter_alert(process_name, exe_path, log_func=None):
    """
    Show a critical alert that an imposter process was detected.

    Args:
        process_name: Name of the imposter process
        exe_path: Path to the executable
        log_func: Optional logging function
    """
    _ensure_popup_thread()
    _popup_queue.put(("imposter", (process_name, exe_path, log_func)))
