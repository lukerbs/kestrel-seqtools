/*
 * Frida script to monitor VirtualProtect calls, and automatically dump
 * memory regions that are made executable. This is crucial for capturing
 * the AnyDesk packer's Stage 2 payload.
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

console.log("[+] Starting VirtualProtect monitor...");
send({ status: 'info', message: 'Script loaded. Now setting up hooks...' });

// ✅ FIX: Wrap the main logic in setImmediate to avoid race conditions on spawn
setImmediate(function() {
    const vpAddress = Module.findExportByName('kernel32', 'VirtualProtect');
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
                        address: address,
                        size: size,
                        protection: protectionString,
                        caller: this.returnAddress
                    };

                    // The .itext section starts at 0x00404000. Highlight this region.
                    if (address.compare(ptr("0x404000")) >= 0 && address.compare(ptr("0x2000000")) < 0) {
                        message.highlight = true;
                        message.note = "!!! This is likely the unpacked payload region !!!";

                        // Read the memory region now that it's being made executable
                        const dump = ptr(address).readByteArray(size);

                        // Send the metadata AND the binary dump back to Python
                        send(message, dump);
                    } else {
                        // For non-highlighted events, just send the metadata
                        send(message);
                    }

                    // Log to the console as well
                    console.log(`[!] VirtualProtect called from ${this.returnAddress} on address: ${address}`);
                    console.log(`    - Size: ${size} bytes`);
                    console.log(`    - New Protection: ${protectionString}`);
                    if (message.highlight) {
                        console.log(`    - NOTE: ${message.note}`);
                    }
                }
            }
        });
    } else {
        send({ status: 'error', message: "[!] Could not find VirtualProtect export in kernel32" });
    }
});
