/**
 * Takopii — DGA / MessageDigest Domain Generation Monitor
 *
 * Catches DomainResolver.md5Hex() and DGA domain generation patterns.
 * Detects seed patterns matching SharkBot V2.8 DGA algorithm:
 * seed = TLD + ISO_week_number + calendar_year
 *
 * Hook 6: MessageDigest DGA detection
 *
 * Usage: frida -U -l dga-monitor.js -f com.target.package
 */

// Hook 6: DGA / MessageDigest Monitor
Java.perform(function() {
    var MessageDigest = Java.use("java.security.MessageDigest");

    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log("[CRYPTO] MessageDigest.getInstance('" + algo + "')");
        console.log("  Stack: " + Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
        return this.getInstance(algo);
    };

    MessageDigest.digest.overload('[B').implementation = function(input) {
        var inputStr = "";
        try {
            inputStr = Java.use("java.lang.String").$new(input);
        } catch(e) {
            inputStr = "<binary " + input.length + " bytes>";
        }
        console.log("[CRYPTO] MessageDigest.digest() input: " + inputStr);

        // DGA detection: input looks like "seed" + week + year
        if (inputStr.match(/^[a-z]+\d{1,2}\d{4}$/)) {
            console.log("  [DGA ALERT] Input matches DGA seed pattern!");
        }

        var result = this.digest(input);
        var hex = "";
        for (var i = 0; i < result.length; i++) {
            hex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
        }
        console.log("[CRYPTO] Digest output: " + hex);
        return result;
    };
});
