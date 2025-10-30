/*
 * OEP Context Inspector
 * 
 * Hooks the Original Entry Point (0x00404000) to intercept the handoff
 * from the packer to the unpacked code. This reveals the dynamic import
 * table and any context structure passed to the application.
 */

console.log("[+] OEP Context Inspector Loaded. Waiting for OEP to be called...");

setImmediate(function() {
    Interceptor.attach(ptr("0x00404000"), {
        onEnter: function(args) {
            console.log(`\n[!] --- OEP at 0x00404000 has been hit! ---`);
            send({ event: 'oep_hit' });

            // Assume the first argument is a pointer to the context/API table
            const contextPtr = args[0];
            console.log(`[+] OEP received context pointer: ${contextPtr}`);

            const resolvedApis = [];
            // Inspect the first 16 pointers in this structure
            for (let i = 0; i < 16; i++) {
                try {
                    const functionPtr = contextPtr.add(i * Process.pointerSize).readPointer();
                    if (functionPtr.isNull()) continue;

                    const debugSymbol = DebugSymbol.fromAddress(functionPtr);
                    resolvedApis.push({
                        index: i,
                        address: functionPtr.toString(),
                        name: debugSymbol.name || "Unknown",
                        module: debugSymbol.moduleName || "N/A"
                    });
                    
                    console.log(`  [${i}] ${functionPtr} -> ${debugSymbol.moduleName}!${debugSymbol.name}`);
                } catch (e) { 
                    // Reached end of table or invalid pointer
                }
            }

            if (resolvedApis.length > 0) {
                console.log("[+] Found resolved APIs passed to OEP:");
                send({ event: 'api_table', table: resolvedApis });
            } else {
                console.log("[!] No valid API pointers found in context structure");
            }
            
            // We only need to run this once
            this.detach();
        }
    });
});

