/*
 * OEP Context Inspector
 * 
 * Hooks the Original Entry Point (0x00404000) to intercept the handoff
 * from the packer to the unpacked code. This reveals the dynamic import
 * table and any context structure passed to the application.
 * 
 * Note: This script should be run AFTER the payload has been unpacked,
 * as the OEP memory region must be executable before we can hook it.
 */

console.log("[+] OEP Context Inspector Loaded. Setting up OEP hook...");

setImmediate(function() {
    try {
        Interceptor.attach(ptr("0x00404000"), {
            onEnter: function(args) {
                console.log(`\n[!] --- OEP at 0x00404000 has been hit! ---`);
                send({ event: 'oep_hit' });

                // Assume the first argument is a pointer to the context/API table
                const contextPtr = args[0];
                console.log(`[+] OEP received context pointer: ${contextPtr}`);
                
                // Expected APIs from static analysis (Section 6.3)
                const expectedApis = [
                    'VirtualAlloc', 'VirtualProtect', 'VirtualFree',
                    'GetProcAddress', 'LoadLibraryA', 'GetModuleHandleA',
                    'CreateThread', 'ExitProcess'
                ];

                // First, validate that this looks like a valid structure
                try {
                    const firstPtr = contextPtr.readPointer();
                    if (firstPtr.isNull()) {
                        console.log("[!] Warning: First pointer in structure is NULL");
                    } else if (!Process.findRangeByAddress(firstPtr)) {
                        console.log("[!] Warning: First pointer doesn't point to valid memory");
                    }
                } catch (e) {
                    console.log(`[!] Warning: Cannot read context structure: ${e.message}`);
                }

                const resolvedApis = [];
                console.log(`[+] Inspecting resolved API table:`);
                
                // Inspect the first 16 pointers in this structure
                for (let i = 0; i < 16; i++) {
                    try {
                        const functionPtr = contextPtr.add(i * Process.pointerSize).readPointer();
                        
                        if (functionPtr.isNull()) {
                            console.log(`  [${i}] NULL (end of table?)`);
                            break; // Likely end of table
                        }

                        const debugSymbol = DebugSymbol.fromAddress(functionPtr);
                        const apiName = debugSymbol.name || "Unknown";
                        const moduleName = debugSymbol.moduleName || "N/A";
                        
                        // Check if this matches our expected APIs
                        const isExpected = expectedApis.some(exp => apiName.includes(exp));
                        const marker = isExpected ? " ✓" : "";
                        
                        resolvedApis.push({
                            index: i,
                            address: functionPtr.toString(),
                            name: apiName,
                            module: moduleName,
                            expected: isExpected
                        });
                        
                        console.log(`  [${i}] ${functionPtr} -> ${moduleName}!${apiName}${marker}`);
                    } catch (e) { 
                        console.log(`  [${i}] <error reading pointer: ${e.message}>`);
                        break; // Stop on first error
                    }
                }

                if (resolvedApis.length > 0) {
                    console.log("[+] Found resolved APIs passed to OEP:");
                    send({ event: 'api_table', table: resolvedApis });
                } else {
                    console.log("[!] No valid API pointers found in context structure");
                    // Still signal completion even if no APIs found
                    send({ event: 'api_table', table: [] });
                }
                
                // We only need to run this once
                this.detach();
            }
        });
        console.log("[+] OEP hook installed at 0x00404000!");
        send({ status: 'info', message: 'OEP hook ready' });
    } catch (e) {
        console.log(`[!] Failed to hook OEP: ${e.message}`);
        send({ status: 'error', message: `Failed to hook OEP: ${e.message}` });
    }
});
