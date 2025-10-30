/*
 * Handoff Structure Interceptor - Hooks BOTH Entry Points
 * 
 * Hooks both unpacked_OEP (0x1000) and FUN_01562950 (0x5CD950)
 * to see which one actually gets called.
 */

console.log("[+] Handoff Structure Interceptor Loaded.");
console.log("[*] Will hook BOTH possible entry points");

let unpackedRegionBase = null;
let alreadyDumped = false;  // Prevent duplicate output

recv('unpacked_region', function(message) {
    unpackedRegionBase = ptr(message.address);
    console.log(`[*] Received unpacked region base: ${unpackedRegionBase}`);
    installHooks();
});

function dumpHandoffStructure(functionName, handoffStructPtr) {
    if (alreadyDumped) {
        console.log(`[*] ${functionName} called, but already dumped structure`);
        return;
    }
    
    alreadyDumped = true;
    
    console.log("\n" + "=".repeat(80));
    console.log(`[!] ${functionName} HAS BEEN HIT!`);
    console.log("=".repeat(80));
    console.log(`[+] Handoff structure pointer: ${handoffStructPtr}`);
    
    if (handoffStructPtr.isNull()) {
        console.log("[!] ERROR: Handoff structure pointer is NULL!");
        send({ event: 'handoff_error', message: 'NULL pointer' });
        return;
    }

    try {
        console.log("\n[*] Reading Handoff Structure:");
        console.log("-".repeat(80));
        
        // First, dump the raw structure bytes to see what we're dealing with
        console.log("[*] Raw structure dump (first 64 bytes):");
        try {
            const rawBytes = handoffStructPtr.readByteArray(64);
            console.log(hexdump(rawBytes, { length: 64, ansi: true }));
        } catch (e) {
            console.log(`[!] Cannot read structure: ${e.message}`);
        }
        console.log("-".repeat(80));
        
        // Read structure fields
        const stringSet1Length = handoffStructPtr.add(0x04).readInt();
        console.log(`[+] Offset +0x04 (String Set #1 Length): ${stringSet1Length}`);
        
        const stringSet1Ptr = handoffStructPtr.add(0x08).readPointer();
        console.log(`[+] Offset +0x08 (String Set #1 Pointer): ${stringSet1Ptr}`);
        
        const stringSet2Length = handoffStructPtr.add(0x0C).readInt();
        console.log(`[+] Offset +0x0C (String Set #2 Length): ${stringSet2Length}`);
        
        const stringSet2Ptr = handoffStructPtr.add(0x10).readPointer();
        console.log(`[+] Offset +0x10 (String Set #2 Pointer): ${stringSet2Ptr}`);
        
        console.log("-".repeat(80));
        
        // Try to read String Set #1
        if (!stringSet1Ptr.isNull() && stringSet1Length > 0 && stringSet1Length < 10000) {
            console.log("\n[*] STRING SET #1:");
            console.log("=".repeat(80));
            try {
                // Try UTF-16 first
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
                console.log(`[!] Error reading as UTF-16: ${e.message}`);
                console.log(`[*] Attempting byte dump instead...`);
                try {
                    const bytes = stringSet1Ptr.readByteArray(Math.min(stringSet1Length * 2, 512));
                    console.log(hexdump(bytes, { length: 512, ansi: true }));
                } catch (e2) {
                    console.log(`[!] Could not dump bytes: ${e2.message}`);
                }
            }
        } else {
            console.log("\n[*] STRING SET #1: NULL or invalid (length: " + stringSet1Length + ")");
        }
        
        // Try to read String Set #2
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
                console.log(`[!] Error reading as UTF-16: ${e.message}`);
                console.log(`[*] Attempting byte dump instead...`);
                try {
                    const bytes = stringSet2Ptr.readByteArray(Math.min(stringSet2Length * 2, 512));
                    console.log(hexdump(bytes, { length: 512, ansi: true }));
                } catch (e2) {
                    console.log(`[!] Could not dump bytes: ${e2.message}`);
                }
            }
        } else {
            console.log("\n[*] STRING SET #2: NULL or invalid (length: " + stringSet2Length + ")");
        }
        
        console.log("\n" + "=".repeat(80));
        console.log("[+] Handoff structure analysis complete!");
        console.log("=".repeat(80) + "\n");
        
        send({ event: 'handoff_complete' });
        
    } catch (e) {
        console.log(`[!] Error analyzing handoff structure: ${e.message}`);
        send({ event: 'handoff_error', message: e.message });
    }
}

function installHooks() {
    if (!unpackedRegionBase) {
        console.log("[!] Cannot install hooks: unpacked region base unknown");
        return;
    }

    try {
        // Hook #1: unpacked_OEP at offset 0x1000
        const oep1Offset = 0x1000;
        const oep1Address = unpackedRegionBase.add(oep1Offset);
        
        console.log(`\n[*] Installing Hook #1: unpacked_OEP`);
        console.log(`    Offset: 0x${oep1Offset.toString(16)}`);
        console.log(`    Address: ${oep1Address}`);
        
        Interceptor.attach(oep1Address, {
            onEnter: function(args) {
                dumpHandoffStructure("unpacked_OEP", args[0]);
            }
        });
        
        // Hook #2: FUN_01562950 at offset 0x5CD950
        const oep2Offset = 0x5CD950;
        const oep2Address = unpackedRegionBase.add(oep2Offset);
        
        console.log(`\n[*] Installing Hook #2: FUN_01562950`);
        console.log(`    Offset: 0x${oep2Offset.toString(16)}`);
        console.log(`    Address: ${oep2Address}`);
        
        Interceptor.attach(oep2Address, {
            onEnter: function(args) {
                dumpHandoffStructure("FUN_01562950", args[0]);
            }
        });
        
        console.log(`\n[+] Both hooks installed successfully!`);
        console.log(`[*] Waiting for execution to reach one of these functions...`);
        console.log(`[!] ⏰ IMPORTANT: Wait at least 60 seconds after this message!`);
        send({ type: 'ready', script: 'handoff_interceptor' });
        
    } catch (e) {
        console.log(`[!] Failed to install hooks: ${e.message}`);
        send({ type: 'error', message: `Failed to install hooks: ${e.message}` });
    }
}

setImmediate(function() {
    console.log("[*] Waiting for unpacked region address from Phase 1...");
});
