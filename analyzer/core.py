import frida
import sys
import time

# --- Configuration ---
# Full path to AnyDesk.exe on your Windows VM
TARGET_EXE_PATH = r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
OUTPUT_FILE = "unpacked_payload.bin"
TIMEOUT = 60  # in seconds, or None to wait forever
# ---------------------

# Global flag to signal when the dump is complete
DUMP_COMPLETE = False

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
    """
    Callback function to handle messages and binary data from JavaScript.
    """
    global DUMP_COMPLETE

    if message['type'] == 'send':
        payload = message['payload']
        # In some Frida versions, the payload is nested.
        if isinstance(payload, dict) and 'payload' in payload and 'type' in payload:
             payload = payload['payload']

        print(f"[*] Received message: {payload}")

        if isinstance(payload, dict) and payload.get('highlight') and data:
            print(f"\n[!] Target memory region identified at {payload['address']} (Size: {payload['size']})")
            print(f"[!] Called from: {payload.get('caller', 'N/A')}")
            print(f"[+] Dumping {len(data)} bytes to '{OUTPUT_FILE}'...")
            
            try:
                with open(OUTPUT_FILE, "wb") as f:
                    f.write(data)
                print(f"[+] Successfully saved unpacked payload to '{OUTPUT_FILE}'!")
                
                print("\n--- Payload Preview (first 256 bytes) ---")
                print(hexdump(data))
                print("------------------------------------------\n")
                
                DUMP_COMPLETE = True
            except IOError as e:
                print(f"[!] Error writing to file: {e}")

    elif message['type'] == 'error':
        print(f"[!] Error: {message['stack']}")
    else:
        print(f"[*] Message: {message}")

def main():
    """
    Spawns the target process in a suspended state, injects hooks,
    then resumes execution to catch unpacking from the very beginning.
    """
    global DUMP_COMPLETE
    try:
        print(f"[*] Spawning '{TARGET_EXE_PATH}' in suspended state...")
        pid = frida.spawn(TARGET_EXE_PATH)
        print(f"[*] Spawned process with PID: {pid}")
        
        print(f"[*] Attaching to PID {pid}...")
        session = frida.attach(pid)
        print(f"[*] Attached successfully!")
    except FileNotFoundError:
        print(f"[!] Executable not found: {TARGET_EXE_PATH}")
        print(f"[!] Please update TARGET_EXE_PATH in the script to the correct path.")
        sys.exit(1)
    except frida.NotSupportedError as e:
        print(f"[!] Frida error: {e}. Is Frida installed on this system?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        sys.exit(1)

    # Load ALL JavaScript files from the js/ directory
    import os
    import glob
    
    js_files = glob.glob("js/*.js")
    if not js_files:
        print("[!] No JavaScript files found in js/ directory")
        sys.exit(1)
    
    print(f"[*] Found {len(js_files)} JavaScript modules to load")
    
    # Combine all JavaScript files into one script
    combined_js = ""
    for js_file in sorted(js_files):
        print(f"    - Loading: {js_file}")
        try:
            with open(js_file, "r", encoding="utf-8") as f:
                combined_js += f"\n// --- {js_file} ---\n"
                combined_js += f.read()
                combined_js += "\n\n"
        except Exception as e:
            print(f"[!] Error loading {js_file}: {e}")
            sys.exit(1)

    try:
        script = session.create_script(combined_js)
        script.on('message', on_message)
        script.load()
        print(f"[*] All {len(js_files)} JavaScript modules injected successfully!")
        
        # NOW resume the process - this is when AnyDesk actually starts executing
        print("[*] Resuming process execution...")
        frida.resume(pid)
        print("[*] Process resumed! Monitoring for VirtualProtect calls...")
        print("[*] Waiting for unpack event...")

        start_time = time.time()
        while not DUMP_COMPLETE:
            if TIMEOUT and (time.time() - start_time) > TIMEOUT:
                print(f"\n[!] Timed out after {TIMEOUT} seconds waiting for unpack event.")
                break
            time.sleep(0.1)

    except frida.InvalidOperationError as e:
        print(f"[!] Error loading script: {e}")
    except KeyboardInterrupt:
        print("\n[*] Detaching due to user request...")
    finally:
        if 'session' in locals() and not session.is_detached:
            session.detach()
        print("[*] Detached successfully.")


if __name__ == "__main__":
    main()
