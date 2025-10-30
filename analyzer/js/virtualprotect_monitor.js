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

setImmediate(function() {
    // ASLR-AWARE CALCULATION
    const baseAddr = Process.enumerateModules()[0].base;
    const itextStart = baseAddr.add(0x4000); // Offset of .itext from base
    const itextEnd = baseAddr.add(0x2000000); // Upper bound for the section

    console.log(`[*] Main module: AnyDesk.exe`);
    console.log(`[*] Current base: ${baseAddr}`);
    console.log(`[*] .itext section range: ${itextStart} - ${itextEnd}`);

    let vpAddress = null;
    
    // Try to find VirtualProtect - it may be in KERNEL32 or KERNELBASE
    try {
        vpAddress = Module.getExportByName('KERNEL32.DLL', 'VirtualProtect');
        console.log(`[+] Found VirtualProtect in KERNEL32: ${vpAddress}`);
    } catch (e) {
        console.log(`[*] Not in KERNEL32, trying KERNELBASE...`);
        try {
            vpAddress = Module.getExportByName('KERNELBASE.dll', 'VirtualProtect');
            console.log(`[+] Found VirtualProtect in KERNELBASE: ${vpAddress}`);
        } catch (e2) {
            console.log(`[!] Failed to find VirtualProtect: ${e2.message}`);
            send({ status: 'error', message: `Could not find VirtualProtect: ${e2.message}` });
            return;
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
                    // Check if the address is within our calculated .itext range
                    if (address.compare(itextStart) >= 0 && address.compare(itextEnd) < 0) {
                        // Check if we've already dumped this region
                        const regionKey = `${address}-${size}`;
                        if (dumpedRegions.has(regionKey)) {
                            console.log(`[*] Region ${address} (${size} bytes) already dumped, skipping`);
                            return;
                        }
                        dumpedRegions.add(regionKey);
                        
                        // Read the memory region now that it's being made executable
                        const dump = ptr(address).readByteArray(size);

                        // Log to console
                        console.log(`[!] VirtualProtect called from ${this.returnAddress} on address: ${address}`);
                        console.log(`    - Size: ${size} bytes (0x${size.toString(16)})`);
                        console.log(`    - New Protection: ${protectionString}`);
                        console.log(`    - NOTE: This is likely the unpacked payload region!`);

                        // Send the metadata AND the binary dump back to Python
                        send({
                            type: 'VirtualProtect',
                            highlight: true,
                            address: address.toString(),
                            size: size,
                            protection: protectionString,
                            caller: this.returnAddress.toString(),
                            note: "!!! This is likely the unpacked payload region !!!"
                        }, dump);
                    } else {
                        // For non-highlighted events, just log (don't send to reduce noise)
                        console.log(`[*] VirtualProtect: ${address} (${size} bytes) -> ${protectionString}`);
                    }
                }
            }
        });
        console.log("[+] VirtualProtect hook installed successfully!");
        send({ status: 'info', message: 'VirtualProtect hook ready' });
    }
});
