/*
 * VirtualProtect Monitor (ASLR-Compatible)
 * 
 * Monitors VirtualProtect calls to detect when memory regions are made executable.
 * This is crucial for capturing the AnyDesk packer's Stage 2 payload.
 * 
 * When the .itext section is made executable, this script automatically dumps it.
 * Dynamically calculates addresses to handle ASLR.
 */

// Mapping of Windows memory protection constants to human-readable strings.
// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
const protFlags = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY"
};

function getProtectionString(prot) {
    if (prot in protFlags) {
        return protFlags[prot];
    }
    // Handle combinations, e.g., PAGE_GUARD
    let protections = [];
    for (const flag in protFlags) {
        if (prot & flag) {
            protections.push(protFlags[flag]);
        }
    }
    return protections.join(' | ') || "UNKNOWN";
}

console.log("[+] VirtualProtect Monitor Loaded. Setting up hooks...");
send({ status: 'info', message: 'VirtualProtect monitor loading...' });

// Track regions we've already dumped to avoid duplicates
const dumpedRegions = new Set();

// Calculate the .itext section range dynamically
let itextStart = null;
let itextEnd = null;

setImmediate(function() {
    // Get the actual base address of the main executable
    const mainModule = Process.enumerateModules()[0];
    const baseAddress = mainModule.base;
    const originalBase = ptr("0x00400000");
    
    console.log(`[*] Main module: ${mainModule.name}`);
    console.log(`[*] Current base: ${baseAddress}`);
    
    // Calculate .itext section address range
    // Original .itext from static analysis: 0x00404000
    const itextOffset = ptr("0x00404000").sub(originalBase);
    itextStart = baseAddress.add(itextOffset);
    itextEnd = baseAddress.add(ptr("0x02000000").sub(originalBase));
    
    console.log(`[*] .itext section range: ${itextStart} - ${itextEnd}`);
    
    let vpAddress = null;
    try {
        vpAddress = Module.findExportByName('kernel32', 'VirtualProtect');
    } catch (e) {
        // Retry with full module name
        try {
            vpAddress = Module.findExportByName('kernel32.dll', 'VirtualProtect');
        } catch (e2) {
            send({ status: 'error', message: `[!] Failed to find VirtualProtect: ${e2.message}` });
        }
    }
    
    if (vpAddress) {
        send({ status: 'info', message: `[*] VirtualProtect found at: ${vpAddress}` });

        Interceptor.attach(vpAddress, {
            onEnter: function(args) {
                if (this.fridaBypass) return;

                const address = args[0];
                const size = args[1].toInt32();
                const protection = args[2].toInt32();
                const protectionString = getProtectionString(protection);

                // Filter for executable permissions
                if (protection & 0xf0) {
                    const message = {
                        type: 'VirtualProtect',
                        address: address.toString(),
                        size: size,
                        protection: protectionString,
                        caller: this.returnAddress.toString()
                    };

                    // Check if this is in the .itext section range
                    if (address.compare(itextStart) >= 0 && address.compare(itextEnd) < 0) {
                        // Check if we've already dumped this region
                        const regionKey = `${address}-${size}`;
                        if (dumpedRegions.has(regionKey)) {
                            console.log(`[*] Region ${address} (${size} bytes) already dumped, skipping`);
                            return;
                        }
                        dumpedRegions.add(regionKey);
                        
                        message.highlight = true;
                        message.note = "!!! This is likely the unpacked payload region !!!";

                        // Read the memory region now that it's being made executable
                        const dump = ptr(address).readByteArray(size);

                        // Log to console
                        console.log(`[!] VirtualProtect called from ${this.returnAddress} on address: ${address}`);
                        console.log(`    - Size: ${size} bytes (0x${size.toString(16)})`);
                        console.log(`    - New Protection: ${protectionString}`);
                        console.log(`    - NOTE: ${message.note}`);

                        // Send the metadata AND the binary dump back to Python
                        send(message, dump);
                    } else {
                        // For non-highlighted events, just log (don't send to reduce noise)
                        console.log(`[*] VirtualProtect: ${address} (${size} bytes) -> ${protectionString}`);
                    }
                }
            }
        });
        console.log("[+] VirtualProtect hook installed successfully!");
        send({ status: 'info', message: 'VirtualProtect hook ready' });
    } else {
        send({ status: 'error', message: "[!] Could not find VirtualProtect export in kernel32" });
    }
});
