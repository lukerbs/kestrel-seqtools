import frida
import sys
import time

# --- Configuration ---
TARGET_PROCESS = "AnyDesk.exe"
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
    Attaches to the target process, injects a JavaScript payload,
    and waits for the unpack event or a timeout.
    """
    global DUMP_COMPLETE
    try:
        print(f"[*] Attaching to '{TARGET_PROCESS}'...")
        session = frida.attach(TARGET_PROCESS)
        print(f"[*] Attached to process with PID: {session.pid}")
    except frida.ProcessNotFoundError:
        print(f"[!] Process '{TARGET_PROCESS}' not found. Is it running?")
        sys.exit(1)
    except frida.NotSupportedError as e:
        print(f"[!] Frida error: {e}. Is the Frida server running with correct permissions?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        sys.exit(1)

    script_path = "analyzer/js/virtualprotect_monitor.js"
    try:
        with open(script_path, "r") as f:
            jscode = f.read()
    except FileNotFoundError:
        print(f"[!] JavaScript agent file not found: {script_path}")
        sys.exit(1)

    try:
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        print("[*] JavaScript payload injected. Monitoring for events...")
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
