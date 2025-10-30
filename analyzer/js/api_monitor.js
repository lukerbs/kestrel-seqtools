/*
 * API Monitor
 * 
 * Traces key Windows API calls related to networking, file I/O, and
 * cryptography to provide a high-level overview of application behavior.
 */

console.log("[+] API Monitor Loaded. Hooking key functions...");

// List of APIs to monitor: [FunctionName: {module, format}]
const interestingApis = {
    'CreateFileW': { 
        module: 'kernel32', 
        format: args => {
            try {
                return `Path: ${args[0].readUtf16String()}`;
            } catch (e) {
                return `Path: <unreadable>`;
            }
        }
    },
    'WriteFile': { 
        module: 'kernel32', 
        format: args => `Handle: ${args[0]}, Bytes: ${args[2].toInt32()}` 
    },
    'ReadFile': { 
        module: 'kernel32', 
        format: args => `Handle: ${args[0]}, Bytes to read: ${args[2].toInt32()}` 
    },
    'connect': { 
        module: 'ws2_32', 
        format: args => {
            try {
                const family = args[1].readU16();
                if (family === 2) { // AF_INET
                    const port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
                    const ip = `${args[1].add(4).readU8()}.${args[1].add(5).readU8()}.${args[1].add(6).readU8()}.${args[1].add(7).readU8()}`;
                    return `IP: ${ip}, Port: ${port}`;
                }
                return `Family: ${family}`;
            } catch (e) {
                return `<error reading sockaddr>`;
            }
        }
    },
    'send': { 
        module: 'ws2_32', 
        format: args => `Socket: ${args[0]}, Bytes: ${args[2].toInt32()}` 
    },
    'recv': { 
        module: 'ws2_32', 
        format: args => `Socket: ${args[0]}, Buffer size: ${args[2].toInt32()}` 
    },
    'CryptEncrypt': { 
        module: 'advapi32', 
        format: args => {
            try {
                return `hKey: ${args[0]}, DataSize: ${args[3].readPointer().toInt32()}`;
            } catch (e) {
                return `hKey: ${args[0]}`;
            }
        }
    },
    'CryptDecrypt': { 
        module: 'advapi32', 
        format: args => {
            try {
                return `hKey: ${args[0]}, DataSize: ${args[3].readPointer().toInt32()}`;
            } catch (e) {
                return `hKey: ${args[0]}`;
            }
        }
    },
    'RegOpenKeyExW': {
        module: 'advapi32',
        format: args => {
            try {
                return `Key: ${args[1].readUtf16String()}`;
            } catch (e) {
                return `Key: <unreadable>`;
            }
        }
    }
};

setImmediate(() => {
    let hookedCount = 0;
    for (const funcName in interestingApis) {
        const api = interestingApis[funcName];
        try {
            const funcAddress = Module.findExportByName(api.module, funcName);
            if (funcAddress) {
                Interceptor.attach(funcAddress, {
                    onEnter: function(args) {
                        const details = api.format(args);
                        const message = `[API] ${api.module}!${funcName} -> ${details}`;
                        console.log(message);
                        send({ event: 'api_call', api: funcName, module: api.module, details: details });
                    }
                });
                hookedCount++;
            }
        } catch (e) {
            // API not available or couldn't hook
        }
    }
    console.log(`[+] Successfully hooked ${hookedCount} APIs`);
});

