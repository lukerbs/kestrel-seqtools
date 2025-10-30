/*
 * Module Base Diagnostic
 * 
 * Quick diagnostic to verify ASLR is the issue and that our address
 * calculation strategy will work.
 */

console.log("[+] Module Base Diagnostic - Checking ASLR...");

setImmediate(function() {
    const modules = Process.enumerateModules();
    
    console.log("\n" + "=".repeat(60));
    console.log("=== Loaded Modules (Top 5) ===");
    console.log("=".repeat(60));
    for (let i = 0; i < Math.min(5, modules.length); i++) {
        const m = modules[i];
        console.log(`[${i}] ${m.name}`);
        console.log(`    Base: ${m.base}`);
        console.log(`    Size: 0x${m.size.toString(16)} (${m.size} bytes)`);
        console.log(`    Path: ${m.path}`);
        console.log("");
    }
    
    const mainModule = modules[0];
    console.log("=".repeat(60));
    console.log("=== ASLR Detection ===");
    console.log("=".repeat(60));
    console.log(`[*] Main module: ${mainModule.name}`);
    console.log(`[*] Actual base address: ${mainModule.base}`);
    console.log(`[*] Expected base (from static analysis): 0x00400000`);
    
    const expectedBase = ptr("0x00400000");
    const actualBase = mainModule.base;
    const delta = actualBase.sub(expectedBase);
    
    if (actualBase.compare(expectedBase) === 0) {
        console.log(`[!] Base addresses MATCH - ASLR appears to be DISABLED`);
        console.log(`[!] This is unusual for modern Windows`);
    } else {
        console.log(`[+] Base addresses DIFFER by: 0x${delta.toString(16)}`);
        console.log(`[+] ASLR is ENABLED - Dynamic address calculation required!`);
    }
    
    console.log("\n" + "=".repeat(60));
    console.log("=== Testing Address Calculations ===");
    console.log("=".repeat(60));
    
    // Test 1: String Decryptor at 0x004036ee
    const expectedDecryptor = ptr("0x004036ee");
    const decryptorOffset = expectedDecryptor.sub(expectedBase);
    const actualDecryptor = actualBase.add(decryptorOffset);
    
    console.log(`\n[Test 1] String Decryptor Function`);
    console.log(`  Original address: ${expectedDecryptor}`);
    console.log(`  Offset from base: 0x${decryptorOffset.toString(16)}`);
    console.log(`  Calculated address: ${actualDecryptor}`);
    
    try {
        const bytes = actualDecryptor.readByteArray(16);
        const hexBytes = Array.from(new Uint8Array(bytes))
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
        console.log(`  [✓] SUCCESS: Can read from ${actualDecryptor}`);
        console.log(`  First 16 bytes: ${hexBytes}`);
    } catch (e) {
        console.log(`  [✗] FAILED: Cannot read from ${actualDecryptor}`);
        console.log(`  Error: ${e.message}`);
    }
    
    // Test 2: OEP at 0x00404000
    const expectedOep = ptr("0x00404000");
    const oepOffset = expectedOep.sub(expectedBase);
    const actualOep = actualBase.add(oepOffset);
    
    console.log(`\n[Test 2] Original Entry Point (OEP)`);
    console.log(`  Original address: ${expectedOep}`);
    console.log(`  Offset from base: 0x${oepOffset.toString(16)}`);
    console.log(`  Calculated address: ${actualOep}`);
    
    try {
        const bytes = actualOep.readByteArray(16);
        const hexBytes = Array.from(new Uint8Array(bytes))
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
        console.log(`  [✓] SUCCESS: Can read from ${actualOep}`);
        console.log(`  First 16 bytes: ${hexBytes}`);
    } catch (e) {
        console.log(`  [✗] FAILED: Cannot read from ${actualOep}`);
        console.log(`  Error: ${e.message}`);
    }
    
    // Test 3: .itext section range
    const expectedItextStart = ptr("0x00404000");
    const itextOffset = expectedItextStart.sub(expectedBase);
    const actualItextStart = actualBase.add(itextOffset);
    
    console.log(`\n[Test 3] .itext Section (Packed Payload)`);
    console.log(`  Original start: ${expectedItextStart}`);
    console.log(`  Calculated start: ${actualItextStart}`);
    
    console.log("\n" + "=".repeat(60));
    console.log("=== Conclusion ===");
    console.log("=".repeat(60));
    
    if (actualBase.compare(expectedBase) !== 0) {
        console.log(`[+] DIAGNOSIS: ASLR is enabled`);
        console.log(`[+] SOLUTION: Use ASLR-compatible scripts (already updated!)`);
        console.log(`[+] The fixed scripts will calculate addresses dynamically`);
        console.log(`[+] Ready to proceed with full analysis!`);
    } else {
        console.log(`[!] DIAGNOSIS: ASLR appears disabled or different issue`);
        console.log(`[!] Further investigation needed`);
    }
    
    console.log("=".repeat(60) + "\n");
    
    send({ event: 'diagnostic_complete' });
});

