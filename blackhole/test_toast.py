#!/usr/bin/env python3
"""
Test script to verify if win10toast works from an elevated process.
Run this script as Administrator to test.

This tests whether the Windows security limitation (elevated processes cannot
send toast notifications) actually applies to win10toast library.
"""

import sys
import os
import time

# Check if running as admin
def is_admin():
    """Check if the current process is running with administrator privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def main():
    print("=" * 60)
    print("  Toast Notification Test (Elevated Process)")
    print("=" * 60)
    print()
    
    # Check admin status
    if not is_admin():
        print("⚠️  WARNING: Not running as Administrator!")
        print("   Please right-click and 'Run as Administrator'")
        print("   This test needs admin privileges to be meaningful.")
        print()
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Exiting...")
            return
        print()
    else:
        print("✓ Running as Administrator")
        print()
    
    # Test win10toast import
    print("[1/3] Testing win10toast import...")
    try:
        from win10toast import ToastNotifier
        print("✓ win10toast imported successfully")
    except ImportError:
        print("✗ ERROR: win10toast not installed!")
        print("   Install with: pip install win10toast")
        print("   Or add to requirements.txt and run: pip install -r requirements.txt")
        input("\nPress Enter to exit...")
        return
    except Exception as e:
        print(f"✗ ERROR importing win10toast: {type(e).__name__}: {e}")
        input("\nPress Enter to exit...")
        return
    
    print()
    
    # Create notifier
    print("[2/3] Creating ToastNotifier...")
    try:
        toaster = ToastNotifier()
        print("✓ ToastNotifier created")
    except Exception as e:
        print(f"✗ ERROR creating ToastNotifier: {type(e).__name__}: {e}")
        input("\nPress Enter to exit...")
        return
    
    print()
    
    # Show test toast
    print("[3/3] Sending test toast notification...")
    print("   Title: 'Test Notification'")
    print("   Message: 'This is a test from an elevated process'")
    print("   Duration: 5 seconds")
    print()
    
    try:
        result = toaster.show_toast(
            "Test Notification",
            "This is a test from an elevated process",
            duration=5,  # 5 seconds
            icon_path=None,  # Optional: path to icon
            threaded=True  # Non-blocking
        )
        
        if result:
            print("✓ Toast notification sent successfully!")
        else:
            print("⚠️  show_toast returned False (may indicate failure)")
        
        print()
        print("👀 Check the bottom-right corner of your screen for the toast.")
        print("   Waiting 6 seconds to see if it appears...")
        print()
        
        # Wait to see if toast appears
        time.sleep(6)
        
        print()
        print("=" * 60)
        print("  Test Complete")
        print("=" * 60)
        print()
        
        if result:
            print("✓ RESULT: win10toast appears to work from elevated process!")
            print("   You can use win10toast in Blackhole for notifications.")
        else:
            print("⚠️  RESULT: win10toast may not work from elevated process.")
            print("   Consider using Tkinter-based toast solution instead.")
        
    except Exception as e:
        print(f"✗ ERROR sending toast: {type(e).__name__}: {e}")
        print()
        print("This suggests win10toast may not work from elevated processes.")
        print("We'll need to use the Tkinter solution instead.")
    
    print()
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()

