import frida
import sys
import time
import os

# --- Configuration ---
TARGET_EXE_PATH = r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
UNPACKED_FILE = "unpacked_payload.bin"
TIMEOUT = 60  # Timeout for each analysis step in seconds
# ---------------------

# Global flag to signal when a one-shot task is complete
TASK_COMPLETE = False

def hexdump(data, length=256):
    """Generates a hexdump of the first `length` bytes of data."""
    if not data:
        return "<empty>"
    data_to_dump = data[:length]
    lines = []
    bytes_per_line = 16
    for i in range(0, len(data_to_dump), bytes_per_line):
        chunk = data_to_dump[i:i + bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")
    if len(data) > length:
        lines.append(f"... ({len(data) - length} more bytes)")
    return "\n".join(lines)

def on_message(message, data):
    """Universal message handler for all analysis scripts."""
    global TASK_COMPLETE
    if message['type'] == 'error':
        print(f"[!] JavaScript Error: {message.get('stack', 'No stack trace')}")
        TASK_COMPLETE = True  # Stop on error
        return

    if message['type'] != 'send':
        return

    payload = message.get('payload', {})
    
    # Only print non-status messages
    if not isinstance(payload, dict) or payload.get('status') != 'info':
        print(f"[*] JS Message: {payload}")

    # --- Logic for the Unpacker ---
    if isinstance(payload, dict) and payload.get('type') == 'VirtualProtect' and payload.get('highlight') and data:
        print(f"\n[!] Unpacker: Target memory region identified at {payload['address']}")
        print(f"[!] Unpacker: Size: {len(data)} bytes (0x{len(data):x})")
        print(f"[!] Unpacker: Called from: {payload.get('caller', 'N/A')}")
        print(f"[+] Unpacker: Dumping to '{UNPACKED_FILE}'...")
        try:
            # Save the binary payload
            with open(UNPACKED_FILE, "wb") as f:
                f.write(data)
            print(f"[+] Unpacker: Successfully saved payload to '{UNPACKED_FILE}'!")
            
            # Save metadata for Ghidra import
            metadata_file = UNPACKED_FILE + ".meta.txt"
            with open(metadata_file, "w") as f:
                f.write(f"AnyDesk Unpacked Payload Metadata\n")
                f.write(f"=" * 60 + "\n")
                f.write(f"Original File: {TARGET_EXE_PATH}\n")
                f.write(f"Dump Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Memory Address: {payload['address']}\n")
                f.write(f"Size: {len(data)} bytes (0x{len(data):x})\n")
                f.write(f"Called From: {payload.get('caller', 'N/A')}\n")
                f.write(f"Protection: {payload.get('protection', 'N/A')}\n")
                f.write(f"\n")
                f.write(f"Ghidra Import Instructions:\n")
                f.write(f"-" * 60 + "\n")
                f.write(f"1. File → Import File → Select '{UNPACKED_FILE}'\n")
                f.write(f"2. Format: Raw Binary\n")
                f.write(f"3. Language: x86:LE:32:default (Windows)\n")
                f.write(f"4. Click 'Options...' button\n")
                f.write(f"5. Set Base Address: {payload['address']}\n")
                f.write(f"6. After import, go to address {payload['address']}\n")
                f.write(f"7. Press 'D' to disassemble, then 'F' to create function\n")
                f.write(f"8. This is the Original Entry Point (OEP)\n")
            print(f"[+] Unpacker: Metadata saved to '{metadata_file}'")
            
            print("\n--- Payload Preview (First 256 bytes) ---")
            print(hexdump(data))
            print("------------------------------------------\n")
            TASK_COMPLETE = True
        except IOError as e:
            print(f"[!] Unpacker: Error writing to file: {e}")

    # --- Logic for the OEP Inspector ---
    elif isinstance(payload, dict) and payload.get('event') == 'api_table':
        print("\n--- OEP Inspector: Resolved API Table Passed to OEP ---")
        for api in payload.get('table', []):
            print(f"  [{api['index']:>2}] {api['address']} -> {api['module']}!{api['name']}")
        print("------------------------------------------------------\n")
        TASK_COMPLETE = True

    # --- Logic for the String Decryptor ---
    elif isinstance(payload, dict) and payload.get('event') == 'decrypted_string':
        unique_count = payload.get('uniqueCount', '?')
        print(f"[{unique_count}] [DECRYPTED] \"{payload['string']}\" (Seed: {payload['seed']})")
    
    elif isinstance(payload, dict) and payload.get('event') == 'string_capture_complete':
        print(f"\n[+] String capture complete! Found {payload['total']} unique API names.")
        TASK_COMPLETE = True

    # --- Logic for the Diagnostic Script ---
    elif isinstance(payload, dict) and payload.get('event') == 'diagnostic_complete':
        TASK_COMPLETE = True
    
    # --- Generic stop condition for scripts that only send one message ---
    elif isinstance(payload, dict) and payload.get('event') == 'oep_hit':
        # The 'api_table' message will follow, which sets TASK_COMPLETE
        pass

def run_analysis(script_path):
    """Spawns the target, injects a script, and waits for it to complete."""
    global TASK_COMPLETE
    TASK_COMPLETE = False
    
    print("\n" + "="*80)
    print(f"[*] EXECUTING ANALYSIS: {os.path.basename(script_path)}")
    print("="*80)

    session = None
    pid = None
    try:
        pid = frida.spawn(TARGET_EXE_PATH)
        session = frida.attach(pid)
        print(f"[*] Spawned & Attached to PID: {pid}")

        with open(script_path, "r", encoding="utf-8") as f:
            jscode = f.read()

        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        print(f"[*] Injected '{os.path.basename(script_path)}'. Waiting for hooks to initialize...")
        
        # Give the setImmediate callbacks time to execute and install hooks
        time.sleep(0.5)
        
        print(f"[*] Resuming process...")
        frida.resume(pid)

        start_time = time.time()
        while not TASK_COMPLETE:
            if time.time() - start_time > TIMEOUT:
                print(f"\n[!] Timed out after {TIMEOUT} seconds.")
                break
            time.sleep(0.1)

    except Exception as e:
        print(f"[!] An error occurred during '{script_path}' analysis: {e}")
    finally:
        if session:
            print("[*] Detaching from process...")
            try:
                session.detach()
            except:
                pass
            # On some systems, the process might need to be explicitly killed
            try:
                if pid:
                    frida.kill(pid)
                    print("[*] Process killed.")
            except Exception:
                pass  # Process might have already terminated

def main():
    """Main function to run all analysis phases sequentially."""
    if not os.path.exists(TARGET_EXE_PATH):
        print(f"[!] FATAL: Target executable not found at '{TARGET_EXE_PATH}'")
        print("[!] Please update the TARGET_EXE_PATH in core.py.")
        sys.exit(1)

    print("\n" + "="*80)
    print("[*] AUTOMATED ANYDESK PACKER ANALYSIS TOOL")
    print("[*] Target: AnyDesk.exe")
    print("[*] Phases: String Decryption → Payload Unpacking → OEP Inspection")
    print("="*80)

    # Diagnostic: Check for ASLR and verify address calculations
    if os.path.exists('js/test_module_base.js'):
        print("\n[*] Running diagnostic to verify ASLR configuration...")
        run_analysis('js/test_module_base.js')
        print("\n[*] Diagnostic complete. Proceeding with full analysis...")
        time.sleep(1)

    # Phase 1: Decrypt all hidden strings from the packer
    if os.path.exists('js/string_decryptor.js'):
        run_analysis('js/string_decryptor.js')
    else:
        print("[!] Skipping Phase 1: string_decryptor.js not found")

    # Phase 2: Wait for the payload to be unpacked and dump it to a file
    if os.path.exists('js/virtualprotect_monitor.js'):
        run_analysis('js/virtualprotect_monitor.js')
    else:
        print("[!] ERROR: virtualprotect_monitor.js not found!")
        sys.exit(1)

    # Phase 3: Inspect the parameters passed from the packer to the payload
    if os.path.exists('js/oep_context_inspector.js'):
        run_analysis('js/oep_context_inspector.js')
    else:
        print("[!] Skipping Phase 3: oep_context_inspector.js not found")
    
    print("\n" + "="*80)
    print("[*] ALL ANALYSIS PHASES COMPLETE")
    if os.path.exists(UNPACKED_FILE):
        print(f"[+] Unpacked payload saved to: {UNPACKED_FILE}")
        print("[*] Next step: Analyze this file in Ghidra (Base Address: 0x00400000)")
    else:
        print("[!] Warning: Unpacked payload file was not created")
    print("="*80)


if __name__ == "__main__":
    main()
