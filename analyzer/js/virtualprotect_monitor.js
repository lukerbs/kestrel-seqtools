/*
 * VirtualProtect Monitor
 * 
 * Monitors VirtualProtect calls to detect when memory regions are made executable.
 * This is crucial for capturing the AnyDesk packer's Stage 2 payload.
 * 
 * When the .itext section at 0x00404000 is made executable, this script
 * automatically dumps it to a file for further analysis.
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

// ✅ FIX: Wrap the main logic in setImmediate to avoid race conditions on spawn
setImmediate(function() {
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

                    // The .itext section starts at 0x00404000. Highlight this region.
                    if (address.compare(ptr("0x404000")) >= 0 && address.compare(ptr("0x2000000")) < 0) {
                        message.highlight = true;
                        message.note = "!!! This is likely the unpacked payload region !!!";

                        // Read the memory region now that it's being made executable
                        const dump = ptr(address).readByteArray(size);

                        // Log to console
                        console.log(`[!] VirtualProtect called from ${this.returnAddress} on address: ${address}`);
                        console.log(`    - Size: ${size} bytes`);
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
