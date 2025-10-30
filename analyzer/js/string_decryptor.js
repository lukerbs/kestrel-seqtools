/*
 * Packer String Decryptor (ASLR-Compatible)
 * 
 * Hooks the custom LCG/XOR decryption routine to automatically decrypt
 * every string the packer uses at runtime.
 * 
 * Dynamically calculates addresses to handle ASLR (Address Space Layout Randomization)
 */

console.log("[+] Packer String Decryptor Loaded. Hooking decryption routine...");

setImmediate(function() {
    try {
        // Get the actual base address of the main executable module
        const mainModule = Process.enumerateModules()[0];
        const baseAddress = mainModule.base;
        const originalBase = ptr("0x00400000");
        
        console.log(`[*] Main module: ${mainModule.name}`);
        console.log(`[*] Current base address: ${baseAddress}`);
        console.log(`[*] Original base address: ${originalBase}`);
        
        // Calculate the offset and add it to the current base
        // Original address from static analysis: 0x004036ee
        const decryptorOffset = ptr("0x004036ee").sub(originalBase);
        const actualDecryptorAddress = baseAddress.add(decryptorOffset);
        
        console.log(`[*] String decryptor offset: 0x${decryptorOffset.toString(16)}`);
        console.log(`[*] Actual decryptor address: ${actualDecryptorAddress}`);
        
        Interceptor.attach(actualDecryptorAddress, {
            onEnter: function(args) {
                // Save arguments: seed, encrypted_data_ptr, length
                this.seed = args[0];
                this.dataPtr = args[1];
                this.length = args[2].toInt32();
                
                // Log the decryption attempt for correlation
                console.log(`[*] Decrypting from ${this.dataPtr} (seed: 0x${this.seed.toString(16)}, len: ${this.length})`);
            },
            onLeave: function(retval) {
                // The return value is a pointer to the decrypted string buffer
                if (!retval.isNull() && this.length > 0 && this.length < 1000) {
                    try {
                        const decryptedString = retval.readCString(this.length);
                        if (decryptedString && decryptedString.length > 0) {
                            send({ 
                                event: 'decrypted_string', 
                                string: decryptedString, 
                                seed: '0x' + this.seed.toString(16).padStart(8, '0'),
                                length: this.length 
                            });
                        }
                    } catch (e) {
                        // Unable to read string
                    }
                }
            }
        });
        console.log("[+] String decryptor hook installed successfully!");
        send({ status: 'info', message: 'String decryptor ready' });
    } catch (e) {
        console.log(`[!] Failed to hook string decryptor: ${e.message}`);
        send({ status: 'error', message: `Failed to hook: ${e.message}` });
    }
});
