/*
 * Packer Transition Hook
 * 
 * This hooks the moment IMMEDIATELY after unpacking when the packer
 * transfers control to the unpacked code. We'll capture the stack
 * and registers at that moment.
 */

console.log("[+] Packer Transition Hook Loaded.");

let unpackedRegionBase = null;
let transitionHooked = false;

recv('unpacked_region', function(message) {
    unpackedRegionBase = ptr(message.address);
    console.log(`[*] Received unpacked region base: ${unpackedRegionBase}`);
    
    if (!transitionHooked) {
        setTimeout(hookTransition, 200);  // Wait for second region
    }
});

function hookTransition() {
    if (!unpackedRegionBase || transitionHooked) {
        return;
    }
    
    transitionHooked = true;
    
    try {
        console.log("\n" + "=".repeat(80));
        console.log("[*] PACKER TRANSITION HOOK: Installing memory access tracker");
        console.log("=".repeat(80));
        
        // Hook the FIRST instruction that executes in the unpacked region
        // This is at offset 0x1000 (the stub OEP)
        const stubOEP = unpackedRegionBase.add(0x1000);
        
        console.log(`[*] Stub OEP: ${stubOEP}`);
        console.log(`[*] Installing instruction tracer...`);
        
        Interceptor.attach(stubOEP, {
            onEnter: function(args) {
                console.log("\n" + "=".repeat(80));
                console.log("[!] PACKER TRANSITION DETECTED - STUB OEP HIT!");
                console.log("=".repeat(80));
                
                // Dump registers
                console.log("\n[*] Register State:");
                console.log(`    EAX: ${this.context.eax}`);
                console.log(`    EBX: ${this.context.ebx}`);
                console.log(`    ECX: ${this.context.ecx}`);
                console.log(`    EDX: ${this.context.edx}`);
                console.log(`    ESI: ${this.context.esi}`);
                console.log(`    EDI: ${this.context.edi}`);
                console.log(`    EBP: ${this.context.ebp}`);
                console.log(`    ESP: ${this.context.esp}`);
                console.log(`    EIP: ${this.context.eip}`);
                
                // Check each register - one of them might point to the handoff structure
                const registers = [
                    { name: 'EAX', ptr: this.context.eax },
                    { name: 'EBX', ptr: this.context.ebx },
                    { name: 'ECX', ptr: this.context.ecx },
                    { name: 'EDX', ptr: this.context.edx },
                    { name: 'ESI', ptr: this.context.esi },
                    { name: 'EDI', ptr: this.context.edi },
                    { name: 'EBP', ptr: this.context.ebp }
                ];
                
                console.log("\n[*] Scanning registers for potential handoff structure...");
                
                for (const reg of registers) {
                    try {
                        if (reg.ptr && !reg.ptr.isNull()) {
                            // Try to read as a potential structure pointer
                            const firstDword = reg.ptr.readU32();
                            const secondDword = reg.ptr.add(4).readU32();
                            
                            // Check if this looks like a valid structure
                            // (length values between 1 and 10000)
                            if (secondDword > 0 && secondDword < 10000) {
                                console.log(`\n[!] ${reg.name} (${reg.ptr}) looks like a structure:`);
                                try {
                                    const dump = reg.ptr.readByteArray(64);
                                    console.log(hexdump(dump, { length: 64, ansi: true }));
                                    
                                    // Try to read as string length + pointer pattern
                                    const strLen = reg.ptr.add(4).readU32();
                                    const strPtr = reg.ptr.add(8).readPointer();
                                    
                                    if (strLen > 0 && strLen < 10000 && !strPtr.isNull()) {
                                        console.log(`    Potential string: length=${strLen}, pointer=${strPtr}`);
                                        try {
                                            const str = strPtr.readUtf16String(Math.min(strLen, 100));
                                            console.log(`    Content preview: "${str.substring(0, 100)}..."`);
                                            
                                            send({
                                                event: 'potential_handoff_structure',
                                                register: reg.name,
                                                address: reg.ptr.toString(),
                                                string_preview: str.substring(0, 200)
                                            });
                                        } catch (e) {
                                            // Not a valid string
                                        }
                                    }
                                } catch (e) {
                                    // Not readable
                                }
                            }
                        }
                    } catch (e) {
                        // Skip invalid registers
                    }
                }
                
                // Also dump the stack
                console.log("\n[*] Stack Dump (first 256 bytes):");
                try {
                    const stackDump = this.context.esp.readByteArray(256);
                    console.log(hexdump(stackDump, { length: 256, ansi: true }));
                } catch (e) {
                    console.log(`[!] Could not read stack: ${e.message}`);
                }
                
                // Check stack arguments
                console.log("\n[*] Checking stack for pushed arguments:");
                try {
                    for (let i = 0; i < 8; i++) {
                        const offset = i * 4;
                        const stackValue = this.context.esp.add(offset).readPointer();
                        console.log(`    [ESP+${offset}]: ${stackValue}`);
                        
                        // Check if this looks like a structure pointer
                        try {
                            if (!stackValue.isNull()) {
                                const testRead = stackValue.add(4).readU32();
                                if (testRead > 0 && testRead < 10000) {
                                    console.log(`        ^ Might be a structure pointer!`);
                                    const dump = stackValue.readByteArray(64);
                                    console.log(hexdump(dump, { length: 64, ansi: true, offset: stackValue }));
                                }
                            }
                        } catch (e) {
                            // Not a valid pointer
                        }
                    }
                } catch (e) {
                    console.log(`[!] Could not analyze stack: ${e.message}`);
                }
                
                console.log("\n" + "=".repeat(80));
                console.log("[+] Transition analysis complete!");
                console.log("=".repeat(80) + "\n");
                
                send({ event: 'transition_captured' });
            }
        });
        
        console.log("[+] Transition hook installed!");
        send({ type: 'ready', script: 'packer_transition_hook' });
        
    } catch (e) {
        console.log(`[!] Failed to install transition hook: ${e.message}`);
        send({ type: 'error', message: e.message });
    }
}

setImmediate(function() {
    console.log("[*] Waiting for unpacked region address...");
});

