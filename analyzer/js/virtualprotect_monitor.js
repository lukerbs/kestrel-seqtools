/*
 * NtProtectVirtualMemory Monitor (ASLR-Compatible, NT API Aware)
 *
 * The AnyDesk packer uses the low-level ntdll!NtProtectVirtualMemory directly
 * instead of kernel32!VirtualProtect to evade common hooks. This monitor
 * targets the correct NT API to catch the unpacking event.
 *
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

console.log("[+] Memory Protection Monitor Loaded.");
console.log("[*] Targeting ntdll!NtProtectVirtualMemory (low-level NT API)");
send({ status: 'info', message: 'Memory protection monitor loading...' });

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

    try {
        const ntProtectAddr = Module.getExportByName('ntdll.dll', 'NtProtectVirtualMemory');
        console.log(`[+] NtProtectVirtualMemory found at: ${ntProtectAddr}`);
        send({ status: 'info', message: `[*] NtProtectVirtualMemory found at: ${ntProtectAddr}` });

        Interceptor.attach(ntProtectAddr, {
            onEnter: function(args) {
                if (this.fridaBypass) return;

                // NtProtectVirtualMemory signature:
                // NTSTATUS NtProtectVirtualMemory(
                //   HANDLE ProcessHandle,      // args[0]
                //   PVOID *BaseAddress,        // args[1] - pointer to address
                //   PSIZE_T RegionSize,        // args[2] - pointer to size
                //   ULONG NewProtect,          // args[3] - direct value
                //   PULONG OldProtect          // args[4] - pointer to old protection
                // );

                try {
                    // Read the actual address and size from the pointers
                    const address = args[1].readPointer();
                    const size = args[2].readPointer().toInt32();
                    const protection = args[3].toInt32();
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
                            console.log(`[!] NtProtectVirtualMemory called from ${this.returnAddress} on address: ${address}`);
                            console.log(`    - Size: ${size} bytes (0x${size.toString(16)})`);
                            console.log(`    - New Protection: ${protectionString}`);
                            console.log(`    - NOTE: This is the unpacked payload region!`);

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
                            console.log(`[*] NtProtectVirtualMemory: ${address} (${size} bytes) -> ${protectionString}`);
                        }
                    }
                } catch (e) {
                    console.log(`[!] Error reading NtProtectVirtualMemory arguments: ${e.message}`);
                }
            }
        });
        console.log("[+] NtProtectVirtualMemory hook installed successfully!");
        send({ status: 'info', message: 'NtProtectVirtualMemory hook ready' });
    } catch (e) {
        console.log(`[!] Failed to hook NtProtectVirtualMemory: ${e.message}`);
        send({ status: 'error', message: `Could not find NtProtectVirtualMemory: ${e.message}` });
    }
});
