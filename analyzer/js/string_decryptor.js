/*
 * Packer String Decryptor
 * 
 * Hooks the custom LCG/XOR decryption routine at 0x004036ee to
 * automatically decrypt every string the packer uses at runtime.
 * 
 * Based on the reverse-engineered algorithm:
 *   next_state = (current_state × 0x19660d) + 0x3c6ef35f
 *   keystream_byte = (next_state >> 12) & 0xFF
 *   plaintext[i] = encrypted[i] ⊕ keystream_byte
 */

console.log("[+] Packer String Decryptor Loaded. Hooking decryption routine at 0x004036ee...");

setImmediate(function() {
    try {
        Interceptor.attach(ptr("0x004036ee"), {
            onEnter: function(args) {
                // Save arguments: seed, encrypted_data_ptr, length
                this.seed = args[0];
                this.dataPtr = args[1];
                this.length = args[2].toInt32();
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

