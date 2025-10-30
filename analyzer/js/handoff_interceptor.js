/*
 * Handoff Structure Interceptor (ASLR-Compatible)
 * 
 * Hooks the TRUE OEP (FUN_01562950) to intercept the handoff structure
 * passed from the packer. This structure contains pre-decrypted Unicode
 * strings that the application will use.
 * 
 * Target: FUN_01562950 at offset 0x162950 from original base 0x00400000
 */

console.log("[+] Handoff Structure Interceptor Loaded.");
console.log("[*] Targeting TRUE OEP: FUN_01562950");

setImmediate(function() {
    try {
        // ASLR-AWARE CALCULATION
        const mainModule = Process.enumerateModules()[0];
        const baseAddr = mainModule.base;
        const originalBase = ptr("0x00400000");
        
        // FUN_01562950 is at 0x01562950 in the unpacked code
        // That's offset 0x162950 from the original base 0x00400000
        const trueOepOffset = ptr("0x01562950").sub(originalBase);
        const actualTrueOep = baseAddr.add(trueOepOffset);

        console.log(`[*] Main module: ${mainModule.name}`);
        console.log(`[*] Current base: ${baseAddr}`);
        console.log(`[*] TRUE OEP offset: 0x${trueOepOffset.toString(16)}`);
        console.log(`[*] Calculated TRUE OEP address: ${actualTrueOep}`);

        Interceptor.attach(actualTrueOep, {
            onEnter: function(args) {
                console.log("\n" + "=".repeat(80));
                console.log(`[!] TRUE OEP (FUN_01562950) HAS BEEN HIT!`);
                console.log("=".repeat(80));
                
                // args[0] = param_1 = pointer to PackerHandoffStructure
                const handoffStructPtr = args[0];
                console.log(`[+] Handoff structure pointer: ${handoffStructPtr}`);
                
                if (handoffStructPtr.isNull()) {
                    console.log("[!] ERROR: Handoff structure pointer is NULL!");
                    send({ event: 'handoff_error', message: 'NULL pointer' });
                    return;
                }

                try {
                    // Read the handoff structure
                    console.log("\n[*] Reading Handoff Structure:");
                    console.log("-".repeat(80));
                    
                    // Offset +0x04: String Set #1 Length
                    const stringSet1Length = handoffStructPtr.add(0x04).readInt();
                    console.log(`[+] String Set #1 Length: ${stringSet1Length} characters`);
                    
                    // Offset +0x08: String Set #1 Data Pointer
                    const stringSet1Ptr = handoffStructPtr.add(0x08).readPointer();
                    console.log(`[+] String Set #1 Pointer: ${stringSet1Ptr}`);
                    
                    // Offset +0x0C: String Set #2 Length
                    const stringSet2Length = handoffStructPtr.add(0x0C).readInt();
                    console.log(`[+] String Set #2 Length: ${stringSet2Length} characters`);
                    
                    // Offset +0x10: String Set #2 Data Pointer
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
                            console.log(`[*] Attempting byte dump instead...`);
                            try {
                                const bytes = stringSet1Ptr.readByteArray(Math.min(stringSet1Length * 2, 256));
                                console.log(hexdump(bytes, { length: 256, ansi: true }));
                            } catch (e2) {
                                console.log(`[!] Could not dump bytes: ${e2.message}`);
                            }
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
                            console.log(`[*] Attempting byte dump instead...`);
                            try {
                                const bytes = stringSet2Ptr.readByteArray(Math.min(stringSet2Length * 2, 256));
                                console.log(hexdump(bytes, { length: 256, ansi: true }));
                            } catch (e2) {
                                console.log(`[!] Could not dump bytes: ${e2.message}`);
                            }
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
                
                // Only run once
                this.detach();
            }
        });
        
        console.log(`[+] TRUE OEP hook installed at ${actualTrueOep}`);
        send({ type: 'ready', script: 'handoff_interceptor' });
        
    } catch (e) {
        console.log(`[!] Failed to hook TRUE OEP: ${e.message}`);
        send({ type: 'error', message: `Failed to hook TRUE OEP: ${e.message}` });
    }
});

