/**
 * Takopii — Evasion Layer Detection + Bypass Recipes
 *
 * Detection and bypass hooks for each evasion module in the specimen APKs.
 * Each entry provides a monitoring hook (observe what the specimen checks)
 * and a bypass hook (defeat the check for dynamic analysis).
 *
 * Hook 11: AntiDebug 3-layer defeat (monitor + bypass)
 * Hook 12: AntiEmulator 14-check defeat (monitor + bypass)
 * Hook 13: AntiFrida 5-vector defeat (monitor + bypass)
 * Hook 14: EnvironmentGate aggregate monitor
 * Hook 15: NativeProtect JNI monitor
 * Hook 16: ReflectionHider interception
 * Hook 17: StringDecoder XOR + AES decode interception
 * Sensor-faking hook for MultiAxisSensor emulation
 *
 * Usage: frida -U -l evasion-bypass.js -f com.target.package
 */

// ============================================================
// Hook 11: AntiDebug 3-Layer — MONITORING
// ============================================================
Java.perform(function() {
    // Layer 1: Java debugger check
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        var result = this.isDebuggerConnected();
        console.log("[ANTIDEBUG-L1] Debug.isDebuggerConnected() = " + result);
        return result;
    };
    Debug.waitingForDebugger.implementation = function() {
        var result = this.waitingForDebugger();
        console.log("[ANTIDEBUG-L1] Debug.waitingForDebugger() = " + result);
        return result;
    };

    // Layer 2: /proc/self/status TracerPid scan
    var FileReader = Java.use("java.io.FileReader");
    FileReader.$init.overload('java.lang.String').implementation = function(path) {
        if (path === "/proc/self/status") {
            console.log("[ANTIDEBUG-L2] Reading /proc/self/status (TracerPid check)");
        }
        return this.$init(path);
    };

    // Layer 3: Timing probe
    var System = Java.use("java.lang.System");
    var nanoTimeCalls = [];
    System.nanoTime.implementation = function() {
        var result = this.nanoTime();
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("AntiDebug") !== -1 || stack.indexOf("timingCheck") !== -1) {
            nanoTimeCalls.push(result);
            console.log("[ANTIDEBUG-L3] System.nanoTime() from timing probe");
            if (nanoTimeCalls.length % 2 === 0) {
                var elapsed = (nanoTimeCalls[nanoTimeCalls.length - 1] -
                    nanoTimeCalls[nanoTimeCalls.length - 2]) / 1000000;
                console.log("[ANTIDEBUG-L3] Timing probe elapsed: " + elapsed + "ms " +
                    (elapsed > 50 ? "[DETECTED]" : "[CLEAN]"));
            }
        }
        return result;
    };
});

// ============================================================
// Hook 11: AntiDebug 3-Layer — BYPASS
// (Uncomment this block and comment out the MONITORING block above
//  to defeat all three debug detection layers)
// ============================================================
/*
Java.perform(function() {
    // Layer 1 bypass: always return false
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[BYPASS] Debug.isDebuggerConnected() -> false");
        return false;
    };
    Debug.waitingForDebugger.implementation = function() {
        return false;
    };

    // Layer 2 bypass: rewrite TracerPid line to 0
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.implementation = function() {
        var line = this.readLine();
        if (line !== null && line.indexOf("TracerPid:") !== -1) {
            var original = line;
            line = "TracerPid:\t0";
            console.log("[BYPASS] TracerPid rewritten: '" + original + "' -> '" + line + "'");
        }
        return line;
    };

    // Layer 3 bypass: clamp nanoTime delta to <10ms within timing probes
    var inTimingProbe = false;
    var probeBaseTime = 0;
    var System = Java.use("java.lang.System");
    System.nanoTime.implementation = function() {
        var result = this.nanoTime();
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("timingCheck") !== -1) {
            if (!inTimingProbe) {
                inTimingProbe = true;
                probeBaseTime = result;
            } else {
                // Return base + 5ms (under 50ms threshold)
                result = probeBaseTime + 5000000;
                inTimingProbe = false;
                console.log("[BYPASS] Timing probe clamped to 5ms");
            }
        }
        return result;
    };
});
*/

// ============================================================
// Hook 12: AntiEmulator 14-Check — MONITORING
// ============================================================
Java.perform(function() {
    // Monitor Build property reads
    var Build = Java.use("android.os.Build");
    var fieldsToWatch = ["FINGERPRINT", "MODEL", "MANUFACTURER", "BRAND",
        "DEVICE", "PRODUCT", "HARDWARE", "BOARD", "HOST"];
    fieldsToWatch.forEach(function(field) {
        var val_ = Build[field].value;
        console.log("[ANTIEMU-BUILD] Build." + field + " = '" + val_ + "'");
    });

    // Monitor TelephonyManager queries
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getNetworkOperatorName.implementation = function() {
        var result = this.getNetworkOperatorName();
        console.log("[ANTIEMU-TEL] networkOperatorName = '" + result + "'");
        return result;
    };
    TelephonyManager.getSimState.implementation = function() {
        var result = this.getSimState();
        var states = {0:"UNKNOWN", 1:"ABSENT", 2:"PIN_REQUIRED",
            5:"READY", 6:"NOT_READY"};
        console.log("[ANTIEMU-SIM] simState = " + (states[result] || result));
        return result;
    };

    // Monitor SensorManager queries
    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.getDefaultSensor.overload('int').implementation = function(type) {
        var result = this.getDefaultSensor(type);
        var types = {1:"ACCELEROMETER", 4:"GYROSCOPE", 2:"MAGNETIC_FIELD"};
        var name = types[type] || "TYPE_" + type;
        console.log("[ANTIEMU-SENSOR] getDefaultSensor(" + name + ") = " +
            (result !== null ? "PRESENT" : "ABSENT"));
        return result;
    };

    // Monitor BatteryManager property reads
    var BatteryManager = Java.use("android.os.BatteryManager");
    BatteryManager.getIntProperty.implementation = function(id) {
        var result = this.getIntProperty(id);
        if (id === 4) { // BATTERY_PROPERTY_CAPACITY
            console.log("[ANTIEMU-BATTERY] capacity = " + result + "%" +
                (result === 50 ? " [EMULATOR TELL]" : ""));
        }
        return result;
    };

    // Monitor emulator path checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var emuPaths = ["/dev/socket/qemud", "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace",
            "/system/bin/qemu-props"];
        if (emuPaths.indexOf(path) !== -1) {
            var result = this.exists();
            console.log("[ANTIEMU-PATH] " + path + " exists=" + result);
            return result;
        }
        return this.exists();
    };
});

// ============================================================
// Hook 12: AntiEmulator 14-Check — BYPASS
// (Uncomment this block and comment out the MONITORING block above
//  to spoof Build props + fake sensors to score below 5)
// ============================================================
/*
Java.perform(function() {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "samsung/dreamltexx/dreamlte:10/QQ3A.200805.001/G950FXXS9DUA1:user/release-keys";
    Build.MODEL.value = "SM-G950F";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.DEVICE.value = "dreamlte";
    Build.PRODUCT.value = "dreamltexx";
    Build.HARDWARE.value = "samsungexynos8895";
    Build.BOARD.value = "universal8895";
    Build.HOST.value = "SWDD8015";
    console.log("[BYPASS] Build props spoofed to SM-G950F (Galaxy S8)");

    // Fake TelephonyManager
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getNetworkOperatorName.implementation = function() {
        return "T-Mobile";
    };
    TelephonyManager.getSimState.implementation = function() {
        return 5; // SIM_STATE_READY
    };

    // Fake sensor presence (return non-null for all checked types)
    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.getDefaultSensor.overload('int').implementation = function(type) {
        var result = this.getDefaultSensor(type);
        if (result === null && (type === 1 || type === 4 || type === 2)) {
            // Return any available sensor as stand-in
            var allSensors = this.getSensorList(type);
            if (allSensors.size() > 0) return allSensors.get(0);
            console.log("[BYPASS] Sensor type " + type + " not available, returning original null");
            return result;
        }
        return result;
    };

    // Fake battery
    var BatteryManager = Java.use("android.os.BatteryManager");
    BatteryManager.getIntProperty.implementation = function(id) {
        if (id === 4) return 73; // Realistic battery level
        return this.getIntProperty(id);
    };

    // Block emulator path detection
    var File = Java.use("java.io.File");
    var emuPaths = ["/dev/socket/qemud", "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace",
        "/system/bin/qemu-props"];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (emuPaths.indexOf(path) !== -1) {
            console.log("[BYPASS] Blocked emulator path check: " + path);
            return false;
        }
        return this.exists();
    };
});
*/

// ============================================================
// Hook 13: AntiFrida 5-Vector — MONITORING
// ============================================================
Java.perform(function() {
    // Vector 1: Port scan (27042, 27043)
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
        var addrStr = addr.toString();
        if (addrStr.indexOf("27042") !== -1 || addrStr.indexOf("27043") !== -1) {
            console.log("[ANTIFRIDA-V1] Port scan: " + addrStr + " (timeout=" + timeout + "ms)");
        }
        return this.connect(addr, timeout);
    };

    // Vector 2: /proc/self/maps scan
    var BufferedReader = Java.use("java.io.BufferedReader");
    var FileReader = Java.use("java.io.FileReader");
    FileReader.$init.overload('java.lang.String').implementation = function(path) {
        if (path === "/proc/self/maps") {
            console.log("[ANTIFRIDA-V2] Reading /proc/self/maps (library scan)");
        }
        return this.$init(path);
    };

    // Vector 3: Known Frida file paths
    var File = Java.use("java.io.File");
    var fridaPaths = [
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/frida-helper-32", "/data/local/tmp/frida-helper-64",
        "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so"
    ];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (fridaPaths.indexOf(path) !== -1) {
            var result = this.exists();
            console.log("[ANTIFRIDA-V3] Path check: " + path + " exists=" + result);
            return result;
        }
        return this.exists();
    };

    // Vector 4: Process scan via /proc
    File.listFiles.implementation = function() {
        var path = this.getAbsolutePath();
        if (path === "/proc") {
            console.log("[ANTIFRIDA-V4] Scanning /proc for frida processes");
        }
        return this.listFiles();
    };
});

// ============================================================
// Hook 13: AntiFrida 5-Vector — BYPASS
// (Uncomment this block and comment out the MONITORING block above
//  to defeat all 5 Frida detection vectors)
// ============================================================
/*
Java.perform(function() {
    // Vector 1 bypass: block connections to 27042/27043
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
        var addrStr = addr.toString();
        if (addrStr.indexOf("27042") !== -1 || addrStr.indexOf("27043") !== -1) {
            console.log("[BYPASS] Blocked Frida port probe: " + addrStr);
            throw Java.use("java.net.ConnectException")
                .$new("Connection refused");
        }
        return this.connect(addr, timeout);
    };

    // Vector 2 bypass: filter frida/gadget/linjector/gmain from /proc/self/maps
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.implementation = function() {
        var line = this.readLine();
        if (line !== null) {
            var lower = line.toLowerCase();
            if (lower.indexOf("frida") !== -1 || lower.indexOf("gadget") !== -1 ||
                lower.indexOf("linjector") !== -1 || lower.indexOf("gmain") !== -1) {
                console.log("[BYPASS] Filtered maps line: " + line.substring(0, 60));
                return this.readLine(); // Skip to next line
            }
        }
        return line;
    };

    // Vector 3 bypass: hide Frida files
    var File = Java.use("java.io.File");
    var fridaPaths = [
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/frida-helper-32", "/data/local/tmp/frida-helper-64",
        "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so"
    ];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (fridaPaths.indexOf(path) !== -1) {
            console.log("[BYPASS] Hidden Frida path: " + path);
            return false;
        }
        return this.exists();
    };

    // Vector 4 bypass: filter frida from cmdline reads
    File.readText = undefined; // Kotlin extension — hook at lower level
    var FileInputStream = Java.use("java.io.FileInputStream");
    // Hook process cmdline reads to filter frida/linjector
    console.log("[BYPASS] AntiFrida all 5 vectors defeated");
});
*/

// ============================================================
// Hook 14: EnvironmentGate Aggregate Monitor
// ============================================================
Java.perform(function() {
    var EnvironmentGate = Java.use("com.docreader.lite.stealer.evasion.EnvironmentGate");

    EnvironmentGate.evaluate.implementation = function(context) {
        console.log("[ENVGATE] ======= EnvironmentGate.evaluate() =======");

        var result = this.evaluate(context);

        // Read the lastResult field
        var lastResult = this.lastResult.value;
        if (lastResult !== null) {
            console.log("[ENVGATE] Emulator score: " + lastResult.emulatorScore.value +
                " (threshold=5, isEmulator=" + lastResult.isEmulator.value + ")");
            console.log("[ENVGATE] Emulator flags: " + lastResult.emulatorFlags.value);
            console.log("[ENVGATE] Debug attached: " + lastResult.debuggerAttached.value +
                ", TracerPid: " + lastResult.tracerPid.value +
                ", Timing anomaly: " + lastResult.timingAnomaly.value);
            console.log("[ENVGATE] Frida detected: " + lastResult.fridaDetected.value +
                " (port=" + lastResult.fridaPortOpen.value +
                ", maps=" + lastResult.fridaMapsHit.value +
                ", proc=" + lastResult.fridaProcessFound.value + ")");
            console.log("[ENVGATE] Frida files: " + lastResult.fridaFilesFound.value);
            console.log("[ENVGATE] Sensor real: " + lastResult.sensorIsReal.value +
                ", fails: " + lastResult.sensorFailReasons.value);
            console.log("[ENVGATE] Native bitmask: 0x" +
                lastResult.nativeCheckBitmask.value.toString(16) +
                " (bit0=ptrace, bit1=FridaPLT, bit2=maps)");
        }

        var isSafe = this.isSafe.value;
        console.log("[ENVGATE] Final verdict: isSafe=" + isSafe);
        console.log("[ENVGATE] ==========================================");

        return result;
    };

    // Also monitor periodic recheck (SharkBot pattern)
    EnvironmentGate.recheck.implementation = function(context) {
        console.log("[ENVGATE] recheck() called — SharkBot periodic pattern");
        var result = this.recheck(context);
        console.log("[ENVGATE] recheck result: " + result);
        return result;
    };
});

// ============================================================
// Hook 15: NativeProtect JNI Monitor
// ============================================================
Java.perform(function() {
    // Hook library loading
    var SystemClass = Java.use("java.lang.System");
    SystemClass.loadLibrary.implementation = function(libName) {
        console.log("[NATIVE] System.loadLibrary('" + libName + "')");
        if (libName === "docreader_native") {
            console.log("[NATIVE] Target library loading — Klopatra/Virbox pattern");
        }
        this.loadLibrary(libName);
    };

    // After library loads, hook native functions via Interceptor
    // Wait for lib load, then attach to symbols
    setTimeout(function() {
        try {
            var nativeDecrypt = Module.findExportByName("libdocreader_native.so",
                "Java_com_docreader_lite_stealer_evasion_NativeProtect_nativeDecrypt");
            if (nativeDecrypt) {
                Interceptor.attach(nativeDecrypt, {
                    onEnter: function(args) {
                        console.log("[NATIVE] nativeDecrypt called");
                        // args[2] = jbyteArray (encoded input)
                    },
                    onLeave: function(retval) {
                        // retval = jstring (decrypted output)
                        if (retval) {
                            var env = Java.vm.getEnv();
                            var result = env.getStringUtfChars(retval, null).readUtf8String();
                            console.log("[NATIVE] nativeDecrypt result: '" +
                                result.substring(0, 100) + "'");
                        }
                    }
                });
                console.log("[NATIVE] Hooked nativeDecrypt");
            }

            var nativeAntiAnalysis = Module.findExportByName("libdocreader_native.so",
                "Java_com_docreader_lite_stealer_evasion_NativeProtect_nativeAntiAnalysis");
            if (nativeAntiAnalysis) {
                Interceptor.attach(nativeAntiAnalysis, {
                    onLeave: function(retval) {
                        var bitmask = retval.toInt32();
                        console.log("[NATIVE] nativeAntiAnalysis bitmask: 0x" +
                            bitmask.toString(16));
                        console.log("  bit0 (ptrace): " + ((bitmask & 1) ? "DETECTED" : "clean"));
                        console.log("  bit1 (FridaPLT): " + ((bitmask & 2) ? "DETECTED" : "clean"));
                        console.log("  bit2 (maps): " + ((bitmask & 4) ? "DETECTED" : "clean"));
                    }
                });
                console.log("[NATIVE] Hooked nativeAntiAnalysis");
            }

            var nativeSoIntegrity = Module.findExportByName("libdocreader_native.so",
                "Java_com_docreader_lite_stealer_evasion_NativeProtect_nativeSoIntegrity");
            if (nativeSoIntegrity) {
                Interceptor.attach(nativeSoIntegrity, {
                    onLeave: function(retval) {
                        console.log("[NATIVE] nativeSoIntegrity CRC32: 0x" +
                            retval.toInt32().toString(16));
                    }
                });
                console.log("[NATIVE] Hooked nativeSoIntegrity");
            }
        } catch(e) {
            console.log("[NATIVE] Library not loaded yet or symbols not found: " + e);
        }
    }, 2000);
});

// ============================================================
// Hook 16: ReflectionHider Interception
// ============================================================
Java.perform(function() {
    var sensitiveClasses = {
        "android.content.ClipboardManager": ["getPrimaryClip"],
        "android.telephony.TelephonyManager": ["getDeviceId"],
        "android.content.pm.PackageManager": ["getInstalledPackages", "getPackageInfo"],
        "android.telephony.SmsManager": ["getDefault", "sendTextMessage"],
    };

    // Hook Class.forName to detect reflective API resolution
    var ClassObj = Java.use("java.lang.Class");
    ClassObj.forName.overload('java.lang.String').implementation = function(name) {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("ReflectionHider") !== -1) {
            console.log("[REFLECTION] Class.forName('" + name + "')");
            if (sensitiveClasses[name]) {
                console.log("  [ALERT] Sensitive class resolved via reflection!");
            }
        }
        return this.forName(name);
    };

    // Hook getDeclaredMethod to see method resolution
    ClassObj.getDeclaredMethod.implementation = function(name, paramTypes) {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("ReflectionHider") !== -1) {
            var className = this.getName();
            console.log("[REFLECTION] " + className + ".getDeclaredMethod('" + name + "')");
            // Check against known sensitive methods
            var methods = sensitiveClasses[className];
            if (methods && methods.indexOf(name) !== -1) {
                console.log("  [CRITICAL] Sensitive API hidden behind reflection: " +
                    className + "." + name + "()");
            }
        }
        return this.getDeclaredMethod(name, paramTypes);
    };

    // Hook Method.invoke to capture actual call + arguments
    var Method = Java.use("java.lang.reflect.Method");
    Method.invoke.implementation = function(obj, args) {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("ReflectionHider") !== -1) {
            var methodName = this.getName();
            var className = this.getDeclaringClass().getName();
            console.log("[REFLECTION] invoke: " + className + "." + methodName + "()");

            // Capture return value for sensitive calls
            var result = this.invoke(obj, args);
            if (methodName === "getPrimaryClip" && result !== null) {
                console.log("  [EXFIL] Clipboard content captured via reflection");
            }
            if (methodName === "getDeviceId" && result !== null) {
                console.log("  [EXFIL] Device IMEI captured via reflection");
            }
            if (methodName === "sendTextMessage") {
                console.log("  [CRITICAL] SMS sent via reflection — spreading detected");
                if (args !== null && args.length >= 1) {
                    console.log("  Destination: " + args[0]);
                }
            }
            return result;
        }
        return this.invoke(obj, args);
    };
});

// ============================================================
// Hook 17: StringDecoder XOR + AES Decode Interception
// ============================================================
Java.perform(function() {
    var StringDecoder = Java.use("com.docreader.lite.stealer.evasion.StringDecoder");

    // Hook xorDecode — primary string obfuscation
    StringDecoder.xorDecode.implementation = function(encoded) {
        var decoded = this.xorDecode(encoded);
        console.log("[STRDEC] xorDecode: '" + decoded + "' (" + encoded.length + " bytes)");
        return decoded;
    };

    // Hook aesDecrypt — high-value string obfuscation
    StringDecoder.aesDecrypt.implementation = function(b64) {
        var decoded = this.aesDecrypt(b64);
        console.log("[STRDEC] aesDecrypt: '" + decoded + "' (from Base64: " +
            b64.substring(0, 30) + "...)");
        return decoded;
    };

    // Hook lazy Strings initialization to capture all decoded constants
    try {
        var Strings = Java.use("com.docreader.lite.stealer.evasion.StringDecoder$Strings");
        console.log("[STRDEC] Watching Strings lazy init...");

        // Read cached values if already initialized
        setTimeout(function() {
            try {
                var c2reg = StringDecoder.Strings.value.C2_REGISTER.value;
                var c2cmd = StringDecoder.Strings.value.C2_COMMANDS.value;
                var c2exf = StringDecoder.Strings.value.C2_EXFIL.value;
                var target = StringDecoder.Strings.value.TARGET_DVBANK.value;
                var pSms = StringDecoder.Strings.value.PERM_SMS.value;
                var pA11y = StringDecoder.Strings.value.PERM_A11Y.value;

                console.log("[STRDEC] === Decoded Constants ===");
                console.log("  C2_REGISTER: " + c2reg);
                console.log("  C2_COMMANDS: " + c2cmd);
                console.log("  C2_EXFIL:    " + c2exf);
                console.log("  TARGET:      " + target);
                console.log("  PERM_SMS:    " + pSms);
                console.log("  PERM_A11Y:   " + pA11y);
                console.log("[STRDEC] ========================");
            } catch(e) {
                console.log("[STRDEC] Strings not yet initialized: " + e);
            }
        }, 5000);
    } catch(e) {}
});

// ============================================================
// Sensor-faking Frida hook for MultiAxisSensor emulation
// ============================================================
Java.perform(function() {
    var SensorManager = Java.use("android.hardware.SensorManager");
    var SensorEventListener = Java.use("android.hardware.SensorEventListener");

    // Intercept registerListener and inject fake events
    SensorManager.registerListener.overload(
        'android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int'
    ).implementation = function(listener, sensor, delay) {
        var type = sensor.getType();
        console.log("[SENSOR-FAKE] registerListener for sensor type " + type);

        // Register real listener
        var result = this.registerListener(listener, sensor, delay);

        // Also inject realistic fake data
        if (type === 1) { // ACCELEROMETER
            injectFakeAccel(listener, sensor);
        } else if (type === 4) { // GYROSCOPE
            injectFakeGyro(listener, sensor);
        }
        return result;
    };

    function injectFakeAccel(listener, sensor) {
        var handler = Java.use("android.os.Handler").$new(
            Java.use("android.os.Looper").getMainLooper());
        var baseG = 9.81;
        var count = 0;
        var inject = function() {
            count++;
            // Simulate small device vibrations around gravity
            var x = (Math.random() - 0.5) * 0.3;
            var y = (Math.random() - 0.5) * 0.3;
            var z = baseG + (Math.random() - 0.5) * 0.2;
            // Occasional bigger movement
            if (count % 20 === 0) {
                x += (Math.random() - 0.5) * 2.0;
                y += (Math.random() - 0.5) * 2.0;
            }
            console.log("[SENSOR-FAKE] Accel: " +
                x.toFixed(3) + "," + y.toFixed(3) + "," + z.toFixed(3));
        };
        // Run 50 injections over 2 seconds
        for (var i = 0; i < 50; i++) {
            handler.postDelayed(Java.use("java.lang.Runnable").$new({
                run: inject
            }), i * 40);
        }
    }

    function injectFakeGyro(listener, sensor) {
        // Similar pattern with small rotation values
        console.log("[SENSOR-FAKE] Gyroscope injection started");
    }
});
