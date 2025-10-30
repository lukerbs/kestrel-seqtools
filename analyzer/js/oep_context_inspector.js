/*
 * OEP Context Inspector (ASLR-Compatible)
 * 
 * Hooks the Original Entry Point to intercept the handoff from the packer
 * to the unpacked code. This reveals the dynamic import table and context
 * structure passed to the application.
 * 
 * Dynamically calculates addresses to handle ASLR.
 */

console.log("[+] OEP Context Inspector Loaded. Setting up OEP hook...");

setImmediate(function() {
    try {
        // ASLR-AWARE CALCULATION
        const baseAddr = Process.enumerateModules()[0].base;
        const oepOffset = 0x4000;
        const actualOepAddress = baseAddr.add(oepOffset);

        console.log(`[*] Main module: AnyDesk.exe`);
        console.log(`[*] Current base: ${baseAddr}`);
        console.log(`[*] OEP offset: 0x${oepOffset.toString(16)}`);
        console.log(`[*] Actual OEP address: ${actualOepAddress}`);

        Interceptor.attach(actualOepAddress, {
            onEnter: function(args) {
                console.log(`\n[!] --- OEP at ${actualOepAddress} has been hit! ---`);
                send({ event: 'oep_hit' });

                // Assume the first argument is a pointer to the context/API table
                const contextPtr = args[0];
                console.log(`[+] OEP received context pointer: ${contextPtr}`);
                
                // Expected APIs from static analysis
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
                    send({ event: 'api_table', table: [] });
                }
                
                // We only need to run this once
                this.detach();
            }
        });
        console.log(`[+] OEP hook installed at ${actualOepAddress}!`);
        send({ type: 'ready', script: 'oep_context_inspector' });  // ← Signal ready
    } catch (e) {
        console.log(`[!] Failed to hook OEP: ${e.message}`);
        send({ type: 'error', message: `Failed to hook OEP: ${e.message}` });
    }
});
