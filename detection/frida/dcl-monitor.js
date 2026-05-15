/**
 * Takopii — DexClassLoader Monitor + DEX Capture
 *
 * Catches PayloadManager.loadAndExecute() and captures DEX bytes
 * before potential anti-forensics deletion.
 *
 * Hook 4: DexClassLoader instantiation + DEX file capture
 *
 * Usage: frida -U -l dcl-monitor.js -f com.target.package
 */

// Hook 4: DexClassLoader Monitor
Java.perform(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
        console.log("[CRITICAL] DexClassLoader instantiated!");
        console.log("  DEX path: " + dexPath);
        console.log("  Opt dir: " + optDir);
        console.log("  Lib path: " + libPath);

        // Capture DEX bytes BEFORE potential deletion (anti-forensics defense)
        var file = Java.use("java.io.File").$new(dexPath);
        if (file.exists()) {
            console.log("  DEX size: " + file.length() + " bytes");
            console.log("  DEX hash: " + hashFile(dexPath));

            // Copy to safe location before malware deletes it
            var safePath = "/data/local/tmp/captured_" + Date.now() + ".dex";
            copyFile(dexPath, safePath);
            console.log("  CAPTURED to: " + safePath);
        }
        return this.$init(dexPath, optDir, libPath, parent);
    };

    function hashFile(path) {
        try {
            var fis = Java.use("java.io.FileInputStream").$new(path);
            var md = Java.use("java.security.MessageDigest").getInstance("SHA-256");
            var buf = Java.array('byte', new Array(4096).fill(0));
            var n;
            while ((n = fis.read(buf)) !== -1) { md.update(buf, 0, n); }
            fis.close();
            var digest = md.digest();
            var hex = "";
            for (var i = 0; i < digest.length; i++) {
                hex += ("0" + (digest[i] & 0xFF).toString(16)).slice(-2);
            }
            return hex;
        } catch(e) { return "error: " + e; }
    }

    function copyFile(src, dst) {
        try {
            var fis = Java.use("java.io.FileInputStream").$new(src);
            var fos = Java.use("java.io.FileOutputStream").$new(dst);
            var buf = Java.array('byte', new Array(8192).fill(0));
            var n;
            while ((n = fis.read(buf)) !== -1) { fos.write(buf, 0, n); }
            fis.close(); fos.close();
        } catch(e) { console.log("  Copy failed: " + e); }
    }
});
