/**
 * Frida Hook Script for SendInput API
 * 
 * This script hooks user32.dll!SendInput and tags all INPUT structures
 * with a magic value (MAGIC_TAG) in the dwExtraInfo field.
 * 
 * This allows the gatekeeper to identify input from remote desktop tools
 * and selectively block it while allowing host input.
 */

// MAGIC_TAG will be replaced by Python before injection
const MAGIC_TAG = {{MAGIC_TAG}};

// --- Step 1: Get the Module Object ---
// Use Process.findModuleByName for safer error handling (returns null if not found)
const user32Module = Process.findModuleByName('user32.dll');

if (!user32Module) {
    // Module not loaded in the target process
    send({type: 'error', message: 'user32.dll module not found in target process'});
} else {
    // --- Step 2: Get the Export from the Module Object ---
    // Use findExportByName on the module object (returns null if not found)
    const sendInput = user32Module.findExportByName('SendInput');

    if (!sendInput) {
        // Function not found within the module
        send({type: 'error', message: 'SendInput export not found in user32.dll'});
    } else {
        // --- Success! Proceed with the hook ---
        // Determine INPUT structure size based on architecture
        var inputSize = Process.pointerSize === 8 ? 40 : 28; // sizeof(INPUT) for 64-bit vs 32-bit

        Interceptor.attach(sendInput, {
            onEnter: function(args) {
                try {
                    // args[0] = cInputs (number of INPUT structures)
                    // args[1] = pInputs (pointer to INPUT array)
                    // args[2] = cbSize (size of INPUT structure)
                    
                    var count = args[0].toInt32();
                    var pInputs = args[1];  // args[1] is already a NativePointer
                    
                    if (count > 0 && pInputs && !pInputs.isNull()) {
                        // Iterate through INPUT structures and tag them
                        for (var i = 0; i < count; i++) {
                            var pInput = pInputs.add(i * inputSize);
                            var type = pInput.readU32();  // INPUT.type (first 4 bytes)
                            
                            if (type === 1) {  // INPUT_KEYBOARD
                                // Offset to ki.dwExtraInfo
                                // 64-bit: 4 (type) + 4 (pad) + 12 (ki fields) = 20
                                // 32-bit: 4 (type) + 12 (ki fields) = 16
                                var extraInfoOffset = Process.pointerSize === 8 ? 20 : 16;
                                // Use writePointer to automatically write 32 or 64 bits
                                pInput.add(extraInfoOffset).writePointer(ptr(MAGIC_TAG));
                            }
                            else if (type === 0) {  // INPUT_MOUSE
                                // Offset to mi.dwExtraInfo
                                // 64-bit: 4 (type) + 4 (pad) + 20 (mi fields) = 28
                                // 32-bit: 4 (type) + 20 (mi fields) = 24
                                var extraInfoOffset = Process.pointerSize === 8 ? 28 : 24;
                                // Use writePointer to automatically write 32 or 64 bits
                                pInput.add(extraInfoOffset).writePointer(ptr(MAGIC_TAG));
                            }
                        }
                        
                        // Notify that we tagged events (only in verbose mode)
                        // send({type: 'tagged', count: count});
                    }
                } catch (e) {
                    send({type: 'error', message: 'Error in onEnter: ' + e.message});
                }
            }
        });
        
        // Signal ready *after* successful attachment
        send({type: 'ready'});
    }
}

