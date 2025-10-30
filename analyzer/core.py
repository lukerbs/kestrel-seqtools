import frida
import sys
import time
import os

# --- Configuration ---
TARGET_EXE_PATH = r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
UNPACKED_FILE = "unpacked_payload.bin"

# Scripts to inject immediately on spawn (before process runs)
PHASE_1_SCRIPTS = ['js/string_decryptor.js', 'js/virtualprotect_monitor.js']

# Scripts to inject AFTER the payload is unpacked (OEP is now executable)
PHASE_2_SCRIPTS = ['js/oep_context_inspector.js']
# ---------------------

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

def main():
    """
    Main function to run a multi-phase dynamic analysis in a single session.
    
    Architecture:
    - Phase 1: Inject early-stage monitors (string decryptor, memory protection)
    - Phase 2: After unpack detected, inject late-stage hooks (OEP inspector)
    """
    session = None
    
    # Use a class to manage state across asynchronous messages
    class AnalysisManager:
        def __init__(self):
            self.phase2_injected = False
            self.unique_string_count = 0

        def on_message(self, message, data):
            """Universal message handler for all analysis scripts."""
            if message.get('type') == 'error':
                print(f"[!] JavaScript Error: {message.get('stack', 'No stack trace')}")
                return

            if message.get('type') != 'send':
                return

            payload = message.get('payload', {})
            
            # Handle 'ready' signal from scripts (like blackhole pattern)
            if isinstance(payload, dict) and payload.get('type') == 'ready':
                script_name = payload.get('script', 'unknown')
                print(f"[+] {script_name} hook active and ready")
                return
            
            # Filter out status messages
            if isinstance(payload, dict) and payload.get('status') == 'info':
                return

            # --- Event: Packer decrypted a string ---
            if isinstance(payload, dict) and payload.get('event') == 'decrypted_string':
                unique_count = payload.get('uniqueCount', '?')
                print(f"[{unique_count}] [DECRYPTED] \"{payload['string']}\" (Seed: {payload['seed']})")
                self.unique_string_count = unique_count

            # --- Event: String capture complete ---
            elif isinstance(payload, dict) and payload.get('event') == 'string_capture_complete':
                print(f"\n[+] String capture complete! Found {payload['total']} unique API names.")

            # --- Event: Payload has been unpacked ---
            elif isinstance(payload, dict) and payload.get('type') == 'VirtualProtect' and payload.get('highlight') and data:
                print(f"\n{'='*80}")
                print(f"[!] UNPACK EVENT DETECTED!")
                print(f"{'='*80}")
                print(f"[!] Memory region identified at {payload['address']}")
                print(f"[!] Size: {len(data)} bytes (0x{len(data):x})")
                print(f"[!] Called from: {payload.get('caller', 'N/A')}")
                print(f"[+] Dumping to '{UNPACKED_FILE}'...")
                
                try:
                    # Save the binary payload
                    with open(UNPACKED_FILE, "wb") as f:
                        f.write(data)
                    print(f"[+] Successfully saved payload to '{UNPACKED_FILE}'!")
                    
                    # Save metadata for Ghidra import
                    metadata_file = UNPACKED_FILE + ".meta.txt"
                    with open(metadata_file, "w", encoding="utf-8") as f:
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
                    print(f"[+] Metadata saved to '{metadata_file}'")
                    
                    print("\n--- Payload Preview (First 256 bytes) ---")
                    print(hexdump(data))
                    print("------------------------------------------\n")
                    
                    # ⭐ CRITICAL: Trigger Phase 2 Injection
                    self.inject_phase2_scripts()
                    
                except IOError as e:
                    print(f"[!] Error writing to file: {e}")

            # --- Event: OEP has been hit ---
            elif isinstance(payload, dict) and payload.get('event') == 'oep_hit':
                print(f"\n[!] OEP at unpacked address has been hit!")

            # --- Event: OEP context/API table received ---
            elif isinstance(payload, dict) and payload.get('event') == 'api_table':
                print("\n" + "="*80)
                print("--- OEP Inspector: Resolved API Table Passed to OEP ---")
                print("="*80)
                apis = payload.get('table', [])
                if apis:
                    for api in apis:
                        marker = " ✓" if api.get('expected') else ""
                        print(f"  [{api['index']:>2}] {api['address']} -> {api['module']}!{api['name']}{marker}")
                else:
                    print("  (No API pointers found or unable to read)")
                print("="*80 + "\n")
                
                print("\n" + "="*80)
                print("[*] ALL ANALYSIS PHASES COMPLETE!")
                print(f"[+] Decrypted {self.unique_string_count} unique strings")
                print(f"[+] Unpacked payload saved to: {UNPACKED_FILE}")
                print(f"[+] OEP inspection complete")
                print("[*] Press Ctrl+C to exit...")
                print("="*80 + "\n")

            # --- Event: A monitored API was called ---
            elif isinstance(payload, dict) and payload.get('event') == 'api_call':
                print(f"[API] {payload.get('api', 'Unknown')} -> {payload.get('details', '')}")

        def inject_phase2_scripts(self):
            """
            Inject Phase 2 scripts after the unpack event.
            This ensures the OEP memory is executable before we try to hook it.
            """
            if self.phase2_injected or not session:
                return
            
            self.phase2_injected = True
            print("\n" + "="*80)
            print("[*] PHASE 2: Injecting late-stage analysis scripts...")
            print("="*80)
            
            # Give the process a moment to finish the memory protection changes
            time.sleep(0.2)
            
            try:
                combined_js = ""
                for script_path in PHASE_2_SCRIPTS:
                    if not os.path.exists(script_path):
                        print(f"[!] Warning: {script_path} not found, skipping")
                        continue
                    
                    print(f"[*] Loading: {script_path}")
                    with open(script_path, "r", encoding="utf-8") as f:
                        combined_js += f"\n// --- {script_path} ---\n"
                        combined_js += f.read()
                        combined_js += "\n\n"
                
                if combined_js:
                    script = session.create_script(combined_js)
                    script.on('message', self.on_message)
                    script.load()
                    print("[+] Phase 2 scripts injected successfully!")
                    print("[*] Now monitoring OEP and application behavior...")
                else:
                    print("[!] No Phase 2 scripts to inject")
                    
            except Exception as e:
                print(f"[!] Failed to inject Phase 2 scripts: {e}")

    analysis_manager = AnalysisManager()

    try:
        if not os.path.exists(TARGET_EXE_PATH):
            print(f"[!] FATAL: Target executable not found at '{TARGET_EXE_PATH}'")
            print("[!] Please update the TARGET_EXE_PATH in core.py.")
            sys.exit(1)

        print("\n" + "="*80)
        print("[*] MULTI-PHASE DYNAMIC ANALYSIS FRAMEWORK")
        print("[*] Target: AnyDesk.exe")
        print("[*] Architecture: Single-session, event-driven")
        print("="*80)
        
        print("\n[*] Spawning target in suspended state...")
        pid = frida.spawn(TARGET_EXE_PATH)
        session = frida.attach(pid)
        print(f"[*] Attached to PID: {pid}")
        
        print("\n[*] PHASE 1: Injecting early-stage monitors...")
        print("-" * 80)
        
        phase1_js = ""
        for script_path in PHASE_1_SCRIPTS:
            if not os.path.exists(script_path):
                print(f"[!] ERROR: {script_path} not found!")
                sys.exit(1)
            
            print(f"[*] Loading: {script_path}")
            with open(script_path, "r", encoding="utf-8") as f:
                phase1_js += f"\n// --- {script_path} ---\n"
                phase1_js += f.read()
                phase1_js += "\n\n"
        
        script = session.create_script(phase1_js)
        script.on('message', analysis_manager.on_message)
        script.load()
        print("[+] Phase 1 scripts loaded successfully!")

        print("\n[*] Resuming process execution...")
        print("[*] Monitoring for unpack event (this triggers Phase 2)...")
        print("-" * 80 + "\n")
        
        frida.resume(pid)
        
        print("[*] Analysis active. Waiting for events...")
        print("[*] Press Ctrl+C to detach and exit.\n")
        
        # Keep the session alive
        sys.stdin.read()

    except KeyboardInterrupt:
        print("\n[*] User interrupt received.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if session and not session.is_detached:
            print("\n[*] Detaching from process...")
            try:
                session.detach()
                print("[*] Detached successfully.")
            except:
                pass

if __name__ == "__main__":
    main()
