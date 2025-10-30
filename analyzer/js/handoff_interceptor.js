/*
 * Handoff Structure Interceptor (ASLR-Compatible) - CORRECTED
 * 
 * Hooks the TRUE OEP (FUN_01562950) to intercept the handoff structure.
 * 
 * CRITICAL: FUN_01562950 is at 0x01562950 in Ghidra's analysis of the
 * unpacked payload, which was loaded at base 0x00F95000.
 * 
 * Offset within unpacked payload = 0x01562950 - 0x00F95000 = 0x5CD950
 */

console.log("[+] Handoff Structure Interceptor Loaded.");
console.log("[*] Targeting TRUE OEP: FUN_01562950");

// Wait for the unpack event to get the actual unpacked region address
let unpackedRegionBase = null;

// Subscribe to messages from other scripts
recv('unpacked_region', function(message) {
    unpackedRegionBase = ptr(message.address);
    console.log(`[*] Received unpacked region base: ${unpackedRegionBase}`);
    installHook();
});

function installHook() {
    if (!unpackedRegionBase) {
        console.log("[!] Cannot install hook: unpacked region base unknown");
        return;
    }

    try {
        // FUN_01562950 is at offset 0x5CD950 from the start of unpacked payload
        // (0x01562950 in Ghidra - 0x00F95000 Ghidra base = 0x5CD950 offset)
        const trueOepOffset = 0x5CD950;
        const actualTrueOep = unpackedRegionBase.add(trueOepOffset);

        console.log(`[*] Unpacked region base: ${unpackedRegionBase}`);
        console.log(`[*] TRUE OEP offset within payload: 0x${trueOepOffset.toString(16)}`);
        console.log(`[*] Calculated TRUE OEP address: ${actualTrueOep}`);

        Interceptor.attach(actualTrueOep, {
            onEnter: function(args) {
                console.log("\n" + "=".repeat(80));
                console.log(`[!] TRUE OEP (FUN_01562950) HAS BEEN HIT!`);
                console.log("=".repeat(80));
                
                const handoffStructPtr = args[0];
                console.log(`[+] Handoff structure pointer: ${handoffStructPtr}`);
                
                if (handoffStructPtr.isNull()) {
                    console.log("[!] ERROR: Handoff structure pointer is NULL!");
                    send({ event: 'handoff_error', message: 'NULL pointer' });
                    return;
                }

                try {
                    console.log("\n[*] Reading Handoff Structure:");
                    console.log("-".repeat(80));
                    
                    const stringSet1Length = handoffStructPtr.add(0x04).readInt();
                    console.log(`[+] String Set #1 Length: ${stringSet1Length} characters`);
                    
                    const stringSet1Ptr = handoffStructPtr.add(0x08).readPointer();
                    console.log(`[+] String Set #1 Pointer: ${stringSet1Ptr}`);
                    
                    const stringSet2Length = handoffStructPtr.add(0x0C).readInt();
                    console.log(`[+] String Set #2 Length: ${stringSet2Length} characters`);
                    
                    const stringSet2Ptr = handoffStructPtr.add(0x10).readPointer();
                    console.log(`[+] String Set #2 Pointer: ${stringSet2Ptr}`);
                    
                    console.log("-".repeat(80));
                    
                    // Read String Set #1
                    if (!stringSet1Ptr.isNull() && stringSet1Length > 0 && stringSet1Length < 10000) {
                        console.log("\n[*] STRING SET #1:");
                        console.log("=".repeat(80));
                        try {
                            const string1 = stringSet1Ptr.readUtf16String(stringSet1Length);
                            console.log(string1);
                            console.log("=".repeat(80));
                            
                            send({ 
                                event: 'handoff_string', 
                                set: 1,
                                length: stringSet1Length,
                                address: stringSet1Ptr.toString(),
                                content: string1
                            });
                        } catch (e) {
                            console.log(`[!] Error reading String Set #1: ${e.message}`);
                        }
                    } else {
                        console.log("\n[*] STRING SET #1: NULL or invalid");
                    }
                    
                    // Read String Set #2
                    if (!stringSet2Ptr.isNull() && stringSet2Length > 0 && stringSet2Length < 10000) {
                        console.log("\n[*] STRING SET #2:");
                        console.log("=".repeat(80));
                        try {
                            const string2 = stringSet2Ptr.readUtf16String(stringSet2Length);
                            console.log(string2);
                            console.log("=".repeat(80));
                            
                            send({ 
                                event: 'handoff_string', 
                                set: 2,
                                length: stringSet2Length,
                                address: stringSet2Ptr.toString(),
                                content: string2
                            });
                        } catch (e) {
                            console.log(`[!] Error reading String Set #2: ${e.message}`);
                        }
                    } else {
                        console.log("\n[*] STRING SET #2: NULL or invalid");
                    }
                    
                    console.log("\n" + "=".repeat(80));
                    console.log("[+] Handoff structure analysis complete!");
                    console.log("=".repeat(80) + "\n");
                    
                    send({ event: 'handoff_complete' });
                    
                } catch (e) {
                    console.log(`[!] Error analyzing handoff structure: ${e.message}`);
                    send({ event: 'handoff_error', message: e.message });
                }
                
                this.detach();
            }
        });
        
        console.log(`[+] TRUE OEP hook installed at ${actualTrueOep}`);
        send({ type: 'ready', script: 'handoff_interceptor' });
        
    } catch (e) {
        console.log(`[!] Failed to hook TRUE OEP: ${e.message}`);
        send({ type: 'error', message: `Failed to hook TRUE OEP: ${e.message}` });
    }
}

// Initial check if we already received the message
setImmediate(function() {
    console.log("[*] Waiting for unpacked region address from Phase 1...");
});
