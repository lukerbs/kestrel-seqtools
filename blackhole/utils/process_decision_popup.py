"""
Process Decision Popup
Shows Tkinter dialogs for whitelist/blacklist decisions on unknown processes.
Uses a dedicated GUI thread with a queue to handle multiple popup requests safely.
"""

import os
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox

import psutil


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
    """
    Show the fake Windows 11 update dialog (called from popup worker thread).

    Three button options:
    - "Install & Restart" -> Whitelist (scammer won't click - takes too long)
    - "Postpone" -> Blacklist (scammer WILL click this)
    - "Learn more" -> Kill process + Delete exe (you can quickly click this)
    """
    log = log_func if log_func else lambda msg, **kwargs: None

    # Create custom dialog window (not using messagebox)
    dialog = tk.Toplevel(root)
    dialog.title("Windows Update")
    dialog.geometry("520x380")
    dialog.resizable(False, False)

    # Make it look like a Windows dialog
    dialog.configure(bg="#f0f0f0")

    # Center on screen
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - (520 // 2)
    y = (dialog.winfo_screenheight() // 2) - (380 // 2)
    dialog.geometry(f"520x380+{x}+{y}")

    # Make it always on top
    dialog.attributes("-topmost", True)
    dialog.focus_force()

    # Result storage
    result = {"decision": None}

    def on_install():
        """Install & Restart button -> Whitelist"""
        result["decision"] = "whitelist"
        log(f"[POPUP] User clicked 'Install & Restart' - whitelisting {process_name}")
        dialog.destroy()

    def on_postpone():
        """Postpone button -> Blacklist"""
        result["decision"] = "blacklist"
        log(f"[POPUP] User clicked 'Postpone' - blacklisting {process_name}")
        dialog.destroy()

    def on_learn_more():
        """Learn more button -> Kill process + Delete exe"""
        result["decision"] = "kill_and_delete"
        log(f"[POPUP] User clicked 'Learn more' - killing and deleting {process_name}")

        # Kill all instances of this process
        try:
            killed_count = 0
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    if proc.info["name"] == process_name and proc.info.get("exe"):
                        if os.path.normpath(proc.info["exe"]).lower() == os.path.normpath(exe_path).lower():
                            proc.kill()
                            killed_count += 1
                            log(f"[POPUP] Killed process {process_name} (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if killed_count > 0:
                log(f"[POPUP] Successfully killed {killed_count} instance(s) of {process_name}")
        except Exception as e:
            log(f"[POPUP] Error killing process: {e}")

        # Delete the executable
        try:
            if os.path.exists(exe_path):
                os.remove(exe_path)
                log(f"[POPUP] Successfully deleted {exe_path}")
            else:
                log(f"[POPUP] File not found (already deleted?): {exe_path}")
        except Exception as e:
            log(f"[POPUP] Error deleting file: {e}")

        dialog.destroy()

    # Message content frame
    content_frame = tk.Frame(dialog, bg="#f0f0f0")
    content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Title
    title_label = tk.Label(
        content_frame,
        text="A Windows 11 update is recommended for this application.",
        font=("Segoe UI", 10),
        bg="#f0f0f0",
        wraplength=480,
        justify=tk.LEFT,
    )
    title_label.pack(anchor=tk.W, pady=(0, 15))

    # Application info
    app_info = tk.Label(
        content_frame,
        text=f"Application: {process_name}\nLocation: {exe_path}",
        font=("Segoe UI", 9),
        bg="#f0f0f0",
        fg="#333333",
        wraplength=480,
        justify=tk.LEFT,
    )
    app_info.pack(anchor=tk.W, pady=(0, 15))

    # Explanation
    explanation = tk.Label(
        content_frame,
        text="This application requires system components that are only available in\n"
        "Windows 11, version 23H2 (Build 22631.4602). Your current version is\n"
        "23H1 (Build 22621.3007).\n\n"
        "Without this update, the application may not function correctly.",
        font=("Segoe UI", 9),
        bg="#f0f0f0",
        wraplength=480,
        justify=tk.LEFT,
    )
    explanation.pack(anchor=tk.W, pady=(0, 15))

    # Update details
    update_details = tk.Label(
        content_frame,
        text="Windows 11 Feature Update (Version 23H2)\n"
        "Update size: 15.5 GB\n"
        "Estimated time: 3h 46m\n"
        "Your PC will restart to complete installation.",
        font=("Segoe UI", 9, "bold"),
        bg="#f0f0f0",
        wraplength=480,
        justify=tk.LEFT,
    )
    update_details.pack(anchor=tk.W, pady=(0, 20))

    # Buttons frame
    button_frame = tk.Frame(dialog, bg="#f0f0f0")
    button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

    # "Learn more" button (left side)
    learn_more_btn = tk.Button(
        button_frame,
        text="Learn more",
        command=on_learn_more,
        font=("Segoe UI", 9),
        width=15,
        relief=tk.FLAT,
        bg="#e1e1e1",
        activebackground="#d0d0d0",
    )
    learn_more_btn.pack(side=tk.LEFT)

    # Spacer
    tk.Frame(button_frame, bg="#f0f0f0").pack(side=tk.LEFT, expand=True)

    # "Postpone" button (right side)
    postpone_btn = tk.Button(
        button_frame,
        text="Postpone",
        command=on_postpone,
        font=("Segoe UI", 9),
        width=15,
        relief=tk.FLAT,
        bg="#e1e1e1",
        activebackground="#d0d0d0",
    )
    postpone_btn.pack(side=tk.RIGHT, padx=(5, 0))

    # "Install & Restart" button (right side, primary)
    install_btn = tk.Button(
        button_frame,
        text="Install & Restart",
        command=on_install,
        font=("Segoe UI", 9),
        width=15,
        relief=tk.FLAT,
        bg="#0078d4",
        fg="white",
        activebackground="#005a9e",
        activeforeground="white",
    )
    install_btn.pack(side=tk.RIGHT)

    # Handle window close (treat as postpone)
    dialog.protocol("WM_DELETE_WINDOW", on_postpone)

    # Wait for dialog to close
    dialog.wait_window()

    # Execute callback with decision
    if callback and result["decision"]:
        callback(result["decision"])


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
