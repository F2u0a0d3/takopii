/**
 * Takopii — Master Monitor (All Hooks Consolidated)
 *
 * Single loadable Frida agent combining all 48 detection hooks.
 * Covers stealer surfaces, evasion monitoring, frontier techniques,
 * persistence, spread modules, and RAT capabilities.
 *
 * Hooks 1-10:  Core stealer surface monitors
 * Hooks 11-17: Evasion layer monitors (monitoring mode, not bypass)
 * Hooks 18-29: Frontier 2025-2026 technique monitors
 * Hooks 30-35b: Deep detection (gates, credentials, screen reading)
 * Hooks 36-47: RAT capabilities (camera, audio, screen, TOTP, USSD,
 *              touch, notifications, contacts, shell, AV-kill, wipe, geo)
 *
 * Usage: frida -U -l master-monitor.js -f com.target.package
 */

// ================================================================
//  SECTION 1: CORE STEALER SURFACE MONITORS (Hooks 1-10)
// ================================================================

// --- Hook 1: ContentResolver SMS Monitor ---
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
        '[Ljava.lang.String;', 'java.lang.String'
    ).implementation = function(uri, proj, sel, selArgs, sort) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
            console.log("[ALERT] SMS ContentResolver query from: " +
                Java.use("android.app.ActivityThread").currentApplication()
                    .getApplicationContext().getPackageName());
            console.log("  URI: " + uriStr);
            console.log("  Projection: " + (proj ? proj.join(", ") : "null"));
            console.log("  Sort: " + sort);
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        // Hook 28: Also catch contact harvesting
        if (uriStr.indexOf("contacts") !== -1 || uriStr.indexOf("phone") !== -1 ||
            uriStr.indexOf("ContactsContract") !== -1) {
            var callerPkg = Java.use("android.app.ActivityThread")
                .currentApplication().getApplicationContext().getPackageName();
            console.log("[HARVEST] Contact query from: " + callerPkg);
            console.log("  URI: " + uriStr);
            console.log("  Projection: " + (proj ? proj.join(", ") : "all"));
        }
        return this.query(uri, proj, sel, selArgs, sort);
    };
});

// --- Hook 2: HttpURLConnection POST Monitor ---
Java.perform(function() {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var URL = Java.use("java.net.URL");

    URL.$init.overload('java.lang.String').implementation = function(url) {
        console.log("[NET] URL created: " + url);
        // Hook 35: Track update channel URLs
        if (url.indexOf("/api/v1/update") !== -1 || url.indexOf("/api/v1/config") !== -1 ||
            url.indexOf("/api/v1/commands") !== -1) {
            console.log("[UPDATE-CH] Config/update request: " + url);
        }
        return this.$init(url);
    };

    HttpURLConnection.setRequestMethod.implementation = function(method) {
        console.log("[NET] HTTP " + method + " -> " + this.getURL().toString());
        return this.setRequestMethod(method);
    };

    HttpURLConnection.getOutputStream.implementation = function() {
        console.log("[EXFIL] POST body being written to: " + this.getURL().toString());
        return this.getOutputStream();
    };

    HttpURLConnection.getResponseCode.implementation = function() {
        var code = this.getResponseCode();
        console.log("[NET] Response " + code + " from " + this.getURL().toString());
        return code;
    };
});

// --- Hook 3: WindowManager Overlay Monitor ---
Java.perform(function() {
    var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");

    WindowManagerImpl.addView.implementation = function(view, params) {
        var lp = Java.cast(params, Java.use("android.view.WindowManager$LayoutParams"));
        var type = lp.type.value;
        // TYPE_APPLICATION_OVERLAY = 2038, TYPE_ACCESSIBILITY_OVERLAY = 2032
        if (type === 2038 || type === 2032) {
            console.log("[CRITICAL] Overlay window created!");
            console.log("  Type: " + (type === 2038 ? "APPLICATION_OVERLAY (2038)" : "ACCESSIBILITY_OVERLAY (2032)"));
            console.log("  Package: " + Java.use("android.app.ActivityThread")
                .currentApplication().getApplicationContext().getPackageName());
            console.log("  Flags: 0x" + lp.flags.value.toString(16));
            if (type === 2032) {
                console.log("  Size: " + lp.width.value + "x" + lp.height.value);
                console.log("  [ALERT] No SYSTEM_ALERT_WINDOW permission needed — " +
                    "A11y grant IS the overlay permission");
            }
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.addView(view, params);
    };
});

// --- Hook 4: DexClassLoader Monitor ---
Java.perform(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
        console.log("[CRITICAL] DexClassLoader instantiated!");
        console.log("  DEX path: " + dexPath);
        console.log("  Opt dir: " + optDir);
        console.log("  Lib path: " + libPath);

        var file = Java.use("java.io.File").$new(dexPath);
        if (file.exists()) {
            console.log("  DEX size: " + file.length() + " bytes");

            var safePath = "/data/local/tmp/captured_" + Date.now() + ".dex";
            try {
                var fis = Java.use("java.io.FileInputStream").$new(dexPath);
                var fos = Java.use("java.io.FileOutputStream").$new(safePath);
                var buf = Java.array('byte', new Array(8192).fill(0));
                var n;
                while ((n = fis.read(buf)) !== -1) { fos.write(buf, 0, n); }
                fis.close(); fos.close();
                console.log("  CAPTURED to: " + safePath);
            } catch(e) { console.log("  Copy failed: " + e); }
        }
        return this.$init(dexPath, optDir, libPath, parent);
    };
});

// --- Hook 5: NotificationListenerService OTP Monitor ---
Java.perform(function() {
    var NLS = Java.use("android.service.notification.NotificationListenerService");

    NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification')
        .implementation = function(sbn) {
        var pkg = sbn.getPackageName();
        var notification = sbn.getNotification();
        var extras = notification.extras;

        var title = extras.getCharSequence("android.title");
        var text = extras.getCharSequence("android.text");
        var bigText = extras.getCharSequence("android.bigText");
        var subText = extras.getCharSequence("android.subText");
        var ticker = notification.tickerText;

        console.log("[NLS] Notification from: " + pkg);
        console.log("  Title: " + (title ? title.toString().substring(0, 50) : "null"));
        console.log("  Text: " + (text ? text.toString().substring(0, 50) : "null"));

        var allText = [title, text, bigText, subText, ticker]
            .filter(function(t) { return t !== null; })
            .map(function(t) { return t.toString(); })
            .join(" ");

        if (allText.match(/\b\d{4,8}\b/) || allText.match(/code|otp|pin|verify/i)) {
            console.log("  [OTP ALERT] Potential OTP in notification!");
        }

        return this.onNotificationPosted(sbn);
    };
});

// --- Hook 6: DGA / MessageDigest Monitor ---
Java.perform(function() {
    var MessageDigest = Java.use("java.security.MessageDigest");

    MessageDigest.digest.overload('[B').implementation = function(input) {
        var inputStr = "";
        try {
            inputStr = Java.use("java.lang.String").$new(input);
        } catch(e) {
            inputStr = "<binary " + input.length + " bytes>";
        }
        console.log("[CRYPTO] MessageDigest.digest() input: " + inputStr);

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

// --- Hook 7: OkHttp Exfil Monitor ---
Java.perform(function() {
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");

        RequestBuilder.url.overload('java.lang.String').implementation = function(url) {
            console.log("[OKHTTP] Request URL: " + url);
            return this.url(url);
        };

        RequestBuilder.post.implementation = function(body) {
            console.log("[OKHTTP-EXFIL] POST request with body");
            try {
                var buf = Java.use("okio.Buffer").$new();
                body.writeTo(buf);
                var bodyStr = buf.readUtf8();
                if (bodyStr.length > 500) bodyStr = bodyStr.substring(0, 500) + "...";
                console.log("  Body: " + bodyStr);
            } catch(e) {}
            return this.post(body);
        };
    } catch(e) {
        console.log("[INFO] OkHttp not present in this specimen");
    }

    // Hook 35: OkHttp response for update channel
    try {
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        ResponseBody.string.implementation = function() {
            var body = this.string();
            if (body.indexOf("c2_host") !== -1 || body.indexOf("targets") !== -1 ||
                body.indexOf("payload_url") !== -1 || body.indexOf("kill") !== -1) {
                console.log("[UPDATE-CH] OkHttp response with config fields:");
                console.log("  Body: " + body.substring(0, 300));
            }
            return body;
        };
    } catch(e) {}
});

// --- Hook 8: BankerA11yService Event Dispatch Monitor ---
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

    AccessibilityService.onAccessibilityEvent.implementation = function(event) {
        var eventType = event.getEventType();
        var pkg = event.getPackageName();
        var pkgStr = pkg ? pkg.toString() : "null";
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();

        if (eventType === 32) {
            console.log("[A11Y-OVERLAY] Window state changed:");
            console.log("  Foreground package: " + pkgStr);
            console.log("  Service package: " + callerPkg);
        }

        if (eventType === 16) {
            var isPassword = event.isPassword();
            console.log("[A11Y-KEYLOG] Text captured" +
                (isPassword ? " [PASSWORD]" : "") + " from: " + pkgStr);
            if (isPassword) {
                console.log("  [CRITICAL] Password field keystroke captured by " + callerPkg);
            }
        }

        if (eventType === 64) {
            console.log("[A11Y-NOTIF] Notification event from: " + pkgStr);
            var text = event.getText();
            if (text && text.size() > 0) {
                var textStr = text.toString();
                if (textStr.match(/\d{4,8}/) || textStr.match(/code|otp|pin|verify/i)) {
                    console.log("  [OTP ALERT] Potential OTP in notification: " +
                        textStr.substring(0, 50));
                }
            }
        }

        return this.onAccessibilityEvent(event);
    };

    // Hook 30: onServiceConnected (arming)
    AccessibilityService.onServiceConnected.implementation = function() {
        console.log("[A11Y-GATE] AccessibilityService.onServiceConnected()");
        console.log("  Service armed — will now receive all UI events");
        return this.onServiceConnected();
    };
});

// --- Hook 9: dispatchGesture ATS Monitor ---
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    // Hook 22: Timing analysis state
    var timingSamples = [];

    AccessibilityService.dispatchGesture.overload(
        'android.accessibilityservice.GestureDescription',
        'android.accessibilityservice.AccessibilityService$GestureResultCallback',
        'android.os.Handler'
    ).implementation = function(gesture, callback, handler) {
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();

        console.log("[ATS-GESTURE] dispatchGesture from: " + callerPkg);
        console.log("  Stroke count: " + gesture.getStrokeCount());
        console.log("  [CRITICAL] Synthetic gesture injection from AccessibilityService");

        // Hook 22: BehaviorMimicry timing analysis
        var now = Date.now();
        timingSamples.push(now);
        if (timingSamples.length > 1) {
            var delta = timingSamples[timingSamples.length - 1] -
                timingSamples[timingSamples.length - 2];
            console.log("[MIMICRY] Gesture delta: " + delta + "ms");

            if (timingSamples.length >= 10) {
                var deltas = [];
                for (var i = 1; i < timingSamples.length; i++) {
                    deltas.push(timingSamples[i] - timingSamples[i - 1]);
                }
                var mean = deltas.reduce(function(a, b) { return a + b; }) / deltas.length;
                var variance = deltas.reduce(function(a, b) {
                    return a + (b - mean) * (b - mean);
                }, 0) / deltas.length;
                var cv = Math.sqrt(variance) / mean;
                var min = Math.min.apply(null, deltas);
                var max = Math.max.apply(null, deltas);

                if (cv > 0.5 && cv < 0.65 && min >= 250 && max <= 3100) {
                    console.log("  [DETECTED] Herodotus original: uniform(300,3000)");
                } else if (cv < 0.1) {
                    console.log("  [DETECTED] Fixed interval — naive automation");
                }
            }
        }

        return this.dispatchGesture(gesture, callback, handler);
    };

    AccessibilityService.performGlobalAction.implementation = function(action) {
        var actions = {1: "BACK", 2: "HOME", 4: "NOTIFICATIONS", 8: "RECENTS"};
        console.log("[ATS-GLOBAL] performGlobalAction: " +
            (actions[action] || "UNKNOWN(" + action + ")"));
        return this.performGlobalAction(action);
    };
});

// --- Hook 10: Clipboard Polling Monitor ---
Java.perform(function() {
    var ClipboardManager = Java.use("android.content.ClipboardManager");

    ClipboardManager.getPrimaryClip.implementation = function() {
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();
        var clip = this.getPrimaryClip();

        if (clip && clip.getItemCount() > 0) {
            var text = clip.getItemAt(0).getText();
            if (text) {
                console.log("[CLIPBOARD] getPrimaryClip() from " + callerPkg);
                console.log("  Content length: " + text.length());
                var stack = Java.use("android.util.Log")
                    .getStackTraceString(Java.use("java.lang.Exception").$new());
                if (stack.indexOf("AccessibilityService") !== -1 ||
                    stack.indexOf("A11y") !== -1) {
                    console.log("  [CRITICAL] Clipboard read from A11y context — Path 2 clipper");
                }
            }
        }
        return clip;
    };
});

// ================================================================
//  SECTION 2: EVASION LAYER MONITORS (Hooks 11-17)
// ================================================================

// --- Hook 11: AntiDebug 3-Layer Monitor ---
Java.perform(function() {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        var result = this.isDebuggerConnected();
        console.log("[ANTIDEBUG-L1] Debug.isDebuggerConnected() = " + result);
        return result;
    };

    var FileReader = Java.use("java.io.FileReader");
    FileReader.$init.overload('java.lang.String').implementation = function(path) {
        if (path === "/proc/self/status") {
            console.log("[ANTIDEBUG-L2] Reading /proc/self/status (TracerPid check)");
        }
        if (path === "/proc/self/maps") {
            console.log("[ANTIFRIDA-V2] Reading /proc/self/maps (library scan)");
        }
        return this.$init(path);
    };
});

// --- Hook 12: AntiEmulator Monitor ---
Java.perform(function() {
    var Build = Java.use("android.os.Build");
    var fieldsToWatch = ["FINGERPRINT", "MODEL", "MANUFACTURER", "BRAND",
        "DEVICE", "PRODUCT", "HARDWARE", "BOARD", "HOST"];
    fieldsToWatch.forEach(function(field) {
        console.log("[ANTIEMU-BUILD] Build." + field + " = '" + Build[field].value + "'");
    });

    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getNetworkOperatorName.implementation = function() {
        var result = this.getNetworkOperatorName();
        console.log("[ANTIEMU-TEL] networkOperatorName = '" + result + "'");
        return result;
    };

    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.getDefaultSensor.overload('int').implementation = function(type) {
        var result = this.getDefaultSensor(type);
        var types = {1:"ACCELEROMETER", 4:"GYROSCOPE", 2:"MAGNETIC_FIELD"};
        console.log("[ANTIEMU-SENSOR] getDefaultSensor(" + (types[type] || type) + ") = " +
            (result !== null ? "PRESENT" : "ABSENT"));
        return result;
    };

    var BatteryManager = Java.use("android.os.BatteryManager");
    BatteryManager.getIntProperty.implementation = function(id) {
        var result = this.getIntProperty(id);
        if (id === 4) {
            console.log("[ANTIEMU-BATTERY] capacity = " + result + "%" +
                (result === 50 ? " [EMULATOR TELL]" : ""));
        }
        return result;
    };
});

// --- Hook 13: AntiFrida Monitor ---
Java.perform(function() {
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
        var addrStr = addr.toString();
        if (addrStr.indexOf("27042") !== -1 || addrStr.indexOf("27043") !== -1) {
            console.log("[ANTIFRIDA-V1] Port scan: " + addrStr);
        }
        if (addrStr.indexOf("9999") !== -1) {
            console.log("[NFC-RELAY] Relay connection to: " + addrStr);
        }
        return this.connect(addr, timeout);
    };

    var File = Java.use("java.io.File");
    var fridaPaths = [
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/frida-helper-32", "/data/local/tmp/frida-helper-64",
        "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so"
    ];
    var emuPaths = ["/dev/socket/qemud", "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace",
        "/system/bin/qemu-props"];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (fridaPaths.indexOf(path) !== -1) {
            var result = this.exists();
            console.log("[ANTIFRIDA-V3] Path check: " + path + " exists=" + result);
            return result;
        }
        if (emuPaths.indexOf(path) !== -1) {
            var result = this.exists();
            console.log("[ANTIEMU-PATH] " + path + " exists=" + result);
            return result;
        }
        return this.exists();
    };
});

// --- Hook 14: EnvironmentGate Aggregate Monitor ---
Java.perform(function() {
    try {
        var EnvironmentGate = Java.use("com.docreader.lite.stealer.evasion.EnvironmentGate");
        EnvironmentGate.evaluate.implementation = function(context) {
            console.log("[ENVGATE] ======= EnvironmentGate.evaluate() =======");
            var result = this.evaluate(context);
            var isSafe = this.isSafe.value;
            console.log("[ENVGATE] Final verdict: isSafe=" + isSafe);
            return result;
        };
    } catch(e) {}
});

// --- Hook 15: NativeProtect JNI Monitor ---
Java.perform(function() {
    var SystemClass = Java.use("java.lang.System");
    SystemClass.loadLibrary.implementation = function(libName) {
        console.log("[NATIVE] System.loadLibrary('" + libName + "')");
        if (libName === "docreader_native") {
            console.log("[NATIVE] Target library loading — Klopatra/Virbox pattern");
        }
        this.loadLibrary(libName);
    };
});

// --- Hook 16: ReflectionHider Interception ---
Java.perform(function() {
    var sensitiveClasses = {
        "android.content.ClipboardManager": ["getPrimaryClip"],
        "android.telephony.TelephonyManager": ["getDeviceId"],
        "android.content.pm.PackageManager": ["getInstalledPackages", "getPackageInfo"],
        "android.telephony.SmsManager": ["getDefault", "sendTextMessage"],
    };

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
});

// --- Hook 17: StringDecoder XOR + AES Monitor ---
Java.perform(function() {
    try {
        var StringDecoder = Java.use("com.docreader.lite.stealer.evasion.StringDecoder");
        StringDecoder.xorDecode.implementation = function(encoded) {
            var decoded = this.xorDecode(encoded);
            console.log("[STRDEC] xorDecode: '" + decoded + "' (" + encoded.length + " bytes)");
            return decoded;
        };
        StringDecoder.aesDecrypt.implementation = function(b64) {
            var decoded = this.aesDecrypt(b64);
            console.log("[STRDEC] aesDecrypt: '" + decoded + "'");
            return decoded;
        };
    } catch(e) {}
});

// ================================================================
//  SECTION 3: FRONTIER MODULE MONITORS (Hooks 18-29)
// ================================================================

// --- Hook 19: HiddenVnc Frame Rate Monitor ---
Java.perform(function() {
    var ImageReader = Java.use("android.media.ImageReader");
    var vncFrameCount = 0;
    var lastVncFrameTime = 0;
    var vncFrameTimes = [];

    ImageReader.acquireLatestImage.implementation = function() {
        vncFrameCount++;
        var now = Date.now();
        if (lastVncFrameTime > 0) {
            vncFrameTimes.push(now - lastVncFrameTime);
            if (vncFrameTimes.length > 10) vncFrameTimes.shift();
            if (vncFrameCount % 10 === 0) {
                var avgFps = 1000 / (vncFrameTimes.reduce(function(a, b) {
                    return a + b;
                }) / vncFrameTimes.length);
                console.log("[VNC] Frame #" + vncFrameCount + " | avg FPS: " + avgFps.toFixed(1));
            }
        }
        lastVncFrameTime = now;
        return this.acquireLatestImage();
    };
});

// --- Hook 20: NfcRelay APDU Monitor ---
Java.perform(function() {
    try {
        var NfcRelayService = Java.use("com.docreader.lite.stealer.frontier.NfcRelayService");
        NfcRelayService.processCommandApdu.implementation = function(apdu, extras) {
            var hexApdu = "";
            for (var i = 0; i < apdu.length; i++) {
                hexApdu += ("0" + (apdu[i] & 0xFF).toString(16)).slice(-2) + " ";
            }
            console.log("[NFC-RELAY] processCommandApdu: " + hexApdu.trim());
            if (apdu.length >= 5 && apdu[0] === 0x00 && (apdu[1] & 0xFF) === 0xA4) {
                console.log("  [CRITICAL] SELECT command — payment AID selection");
            }
            return this.processCommandApdu(apdu, extras);
        };
    } catch(e) {}
});

// --- Hook 21: ResidentialProxy Session Monitor ---
Java.perform(function() {
    var ServerSocket = Java.use("java.net.ServerSocket");
    ServerSocket.$init.overload('int').implementation = function(port) {
        console.log("[PROXY] ServerSocket bind on port " + port);
        if (port >= 1080 && port <= 1090) {
            console.log("  [ALERT] SOCKS5 proxy port range — Mirax pattern");
        }
        return this.$init(port);
    };

    ServerSocket.accept.implementation = function() {
        var socket = this.accept();
        console.log("[PROXY] Connection accepted from: " +
            socket.getRemoteSocketAddress().toString());
        return socket;
    };
});

// --- Hook 23: SsoHijacker Intercept ---
Java.perform(function() {
    var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    var ssoApps = [
        "com.azure.authenticator", "com.okta.android",
        "com.duosecurity.duomobile", "com.google.android.apps.authenticator2",
        "com.authy.authy"
    ];

    ANI.performAction.overload('int').implementation = function(action) {
        if (action === 16) {
            var pkg = this.getPackageName();
            var pkgStr = pkg ? pkg.toString() : "";
            var text = this.getText();
            var textStr = text ? text.toString().toLowerCase() : "";

            var isSsoApp = ssoApps.some(function(sso) { return pkgStr.indexOf(sso) !== -1; });
            var isApproveButton = ["approve", "allow", "confirm", "verify",
                "accept", "it's me", "onayla", "aprobar"]
                .some(function(p) { return textStr.indexOf(p) !== -1; });

            if (isSsoApp && isApproveButton) {
                console.log("[SSO-HIJACK] AUTO-APPROVE detected!");
                console.log("  SSO app: " + pkgStr);
                console.log("  [CRITICAL] Vespertine MFA bypass — sub-500ms approval");
            }
        }
        return this.performAction(action);
    };
});

// --- Hook 24: TeeOffload Key + Crypto Monitor ---
Java.perform(function() {
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    KeyGenerator.init.overload('java.security.spec.AlgorithmParameterSpec')
        .implementation = function(params) {
        var paramsStr = params.toString();
        console.log("[TEE] KeyGenerator.init: " + paramsStr);
        if (paramsStr.indexOf("AndroidKeyStore") !== -1 ||
            paramsStr.indexOf("StrongBox") !== -1) {
            console.log("  [ALERT] TEE-backed key generation — Drelock pattern");
        }
        return this.init(params);
    };

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var mode = this.getOpmode();
        var algo = this.getAlgorithm();
        if ((algo.indexOf("AES") !== -1 || algo.indexOf("GCM") !== -1) && mode === 1) {
            console.log("[TEE] Cipher.doFinal ENCRYPT — " + algo);
            console.log("  [CAPTURE] Plaintext captured before TEE encryption");
        }
        return this.doFinal(input);
    };

    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
        if (type === "AndroidKeyStore") {
            console.log("[TEE] KeyStore.getInstance('AndroidKeyStore')");
        }
        return this.getInstance(type);
    };
});

// --- Hook 25: YamuxProxy Stream Monitor ---
Java.perform(function() {
    var OutputStream = Java.use("java.io.OutputStream");
    OutputStream.write.overload('[B', 'int', 'int').implementation = function(buf, off, len) {
        if (len >= 12 && (buf[off] & 0xFF) === 0x00) {
            var type = buf[off + 1] & 0xFF;
            var flags = ((buf[off + 2] & 0xFF) << 8) | (buf[off + 3] & 0xFF);
            var streamId = ((buf[off + 4] & 0xFF) << 24) | ((buf[off + 5] & 0xFF) << 16) |
                ((buf[off + 6] & 0xFF) << 8) | (buf[off + 7] & 0xFF);
            var payloadLen = ((buf[off + 8] & 0xFF) << 24) | ((buf[off + 9] & 0xFF) << 16) |
                ((buf[off + 10] & 0xFF) << 8) | (buf[off + 11] & 0xFF);

            var types = {0: "DATA", 1: "WINDOW_UPDATE", 2: "PING", 3: "GO_AWAY"};
            console.log("[YAMUX] Frame: type=" + (types[type] || type) +
                " stream=" + streamId + " len=" + payloadLen);
        }
        return this.write(buf, off, len);
    };
});

// --- Hook 26: PerBuildObfuscation Seed Capture ---
Java.perform(function() {
    var SecureRandom = Java.use("java.security.SecureRandom");
    SecureRandom.$init.overload('[B').implementation = function(seed) {
        console.log("[PERBUILD] SecureRandom seeded with " + seed.length + " bytes");
        if (seed.length === 8) {
            var hex = "";
            for (var i = 0; i < seed.length; i++) {
                hex += ("0" + (seed[i] & 0xFF).toString(16)).slice(-2);
            }
            console.log("  Seed hex: " + hex);
            console.log("  [CAPTURE] With this seed, defender can reconstruct full decode pipeline");
        }
        return this.$init(seed);
    };
});

// --- Hook 27: EarlyInitProvider Execution Order ---
Java.perform(function() {
    var ContentProvider = Java.use("android.content.ContentProvider");
    ContentProvider.onCreate.implementation = function() {
        var className = this.getClass().getName();
        console.log("[PERSISTENCE] ContentProvider.onCreate: " + className + " at " + Date.now());
        if (className.indexOf("EarlyInit") !== -1 || className.indexOf("Init") !== -1) {
            console.log("  [ALERT] Init-hook ContentProvider — pre-Application execution");
        }
        return this.onCreate();
    };

    var Application = Java.use("android.app.Application");
    Application.onCreate.implementation = function() {
        console.log("[PERSISTENCE] Application.onCreate at " + Date.now());
        return this.onCreate();
    };
});

// --- Hook 29: SmsWorm Rate-Limited Spread Monitor ---
Java.perform(function() {
    var smsSendTimes = [];
    var smsDestinations = [];

    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.overload(
        'java.lang.String', 'java.lang.String', 'java.lang.String',
        'android.app.PendingIntent', 'android.app.PendingIntent'
    ).implementation = function(dest, sc, body, sentIntent, deliveryIntent) {
        var now = Date.now();
        smsSendTimes.push(now);
        smsDestinations.push(dest);

        console.log("[SMS-WORM] sendTextMessage to: " + dest);
        console.log("  Total sent: " + smsSendTimes.length);

        if (smsSendTimes.length > 1) {
            var delta = (now - smsSendTimes[smsSendTimes.length - 2]) / 1000;
            if (delta >= 25 && delta <= 65) {
                console.log("  [ALERT] Rate-limited spreading pattern (30-60s interval)");
            }
        }

        var unique = [];
        smsDestinations.forEach(function(d) { if (unique.indexOf(d) === -1) unique.push(d); });
        if (unique.length > 5) {
            console.log("  [CRITICAL] SMS sent to " + unique.length + " unique recipients — worm spreading!");
        }

        if (body.match(/https?:\/\/[^\s]+/)) {
            console.log("  [ALERT] URL in SMS body — install-link lure");
        }

        return this.sendTextMessage(dest, sc, body, sentIntent, deliveryIntent);
    };
});

// ================================================================
//  SECTION 4: DEEP DETECTION (Hooks 30-35b)
// ================================================================

// --- Hook 30: AccessibilityEngine Gate (see Hook 8 section) ---
// Integrated into Hook 8 block above

// --- Hook 31: CredentialStore Buffer Monitor ---
Java.perform(function() {
    try {
        var CredentialStore = Java.use("com.skyweather.forecast.core.CredentialStore");
        CredentialStore.drain.implementation = function() {
            var result = this.drain();
            console.log("[CREDSTORE] drain() — " + result.size() + " events flushed for exfil");
            return result;
        };
        CredentialStore.peekAll.implementation = function() {
            var result = this.peekAll();
            console.log("[CREDSTORE] peekAll() — " + result.size() + " events (ATS OTP lookup)");
            return result;
        };
    } catch(e) {}
});

// --- Hook 33: SmsInterceptor Priority Monitor ---
Java.perform(function() {
    var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
    BroadcastReceiver.onReceive.implementation = function(context, intent) {
        var action = intent.getAction();
        if (action && action.indexOf("SMS_RECEIVED") !== -1) {
            console.log("[SMS-INTERCEPT] onReceive: " + action);
            console.log("  Receiver: " + this.getClass().getName());
        }
        var result = this.onReceive(context, intent);
        if (action && action.indexOf("SMS_RECEIVED") !== -1) {
            if (this.getAbortBroadcast()) {
                console.log("  [CRITICAL] abortBroadcast() called — SMS notification suppressed!");
            }
        }
        return result;
    };
});

// --- Hook 34: OtpExtractor Confidence Scoring ---
Java.perform(function() {
    try {
        var OtpExtractor = Java.use("com.skyweather.forecast.core.OtpExtractor");
        OtpExtractor.extract.implementation = function(text) {
            var result = this.extract(text);
            if (result !== null) {
                console.log("[OTP-EXTRACT] code=" + result.code.value +
                    " confidence=" + result.confidence.value);
            }
            return result;
        };
    } catch(e) {
        try {
            var OtpExtractor2 = Java.use("com.docreader.lite.stealer.OtpExtractor");
            OtpExtractor2.extract.implementation = function(text) {
                var result = this.extract(text);
                if (result !== null) {
                    console.log("[OTP-EXTRACT] code=" + result.code.value +
                        " confidence=" + result.confidence.value);
                }
                return result;
            };
        } catch(e2) {}
    }
});

// --- Hook 35: UpdateChannel (see Hook 2 and Hook 7 sections) ---
// Integrated into URL and OkHttp hooks above

// --- Hook 35b: ScreenReader A11y Tree Traversal ---
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    AccessibilityService.getRootInActiveWindow.overload()
        .implementation = function() {
        var root = this.getRootInActiveWindow();
        if (root !== null) {
            console.log("[SCREEN-READ] getRootInActiveWindow() -> pkg=" + root.getPackageName());
        }
        return root;
    };

    var childCallCount = 0;
    var lastTreeTime = 0;
    var NodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

    NodeInfo.getChild.overload('int').implementation = function(index) {
        var child = this.getChild(index);
        childCallCount++;
        var now = Date.now();
        if (now - lastTreeTime > 200) {
            if (childCallCount > 50) {
                console.log("[SCREEN-READ] Deep tree traversal: " + childCallCount +
                    " getChild() calls — ATS pattern");
            }
            childCallCount = 1;
        }
        lastTreeTime = now;
        return child;
    };

    NodeInfo.findAccessibilityNodeInfosByViewId.implementation = function(viewId) {
        var result = this.findAccessibilityNodeInfosByViewId(viewId);
        if (viewId && (viewId.indexOf("amount") !== -1 || viewId.indexOf("iban") !== -1 ||
            viewId.indexOf("confirm") !== -1 || viewId.indexOf("transfer") !== -1 ||
            viewId.indexOf("otp") !== -1 || viewId.indexOf("password") !== -1)) {
            console.log("[SCREEN-READ] Banking view ID searched: " + viewId);
        }
        return result;
    };
});

// ================================================================
//  SECTION 5: RAT CAPABILITY MONITORS (Hooks 36-47)
//  Families: Brokewell, Crocodilus, FakeCall, TrickMo, ToxicPanda,
//            Cerberus, BRATA, SpyNote
// ================================================================

// --- Hook 36: Camera2 Silent Capture ---
Java.perform(function() {
    var CameraManager = Java.use("android.hardware.camera2.CameraManager");
    CameraManager.openCamera.overload(
        'java.lang.String',
        'android.hardware.camera2.CameraDevice$StateCallback',
        'android.os.Handler'
    ).implementation = function(cameraId, callback, handler) {
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();
        console.log("[RAT-CAMERA] openCamera(id=" + cameraId + ") from: " + callerPkg);
        return this.openCamera(cameraId, callback, handler);
    };

    var CameraDevice = Java.use("android.hardware.camera2.CameraDevice");
    CameraDevice.createCaptureRequest.implementation = function(templateType) {
        if (templateType === 2) {
            console.log("[RAT-CAMERA] STILL_CAPTURE without preview — silent photo");
        }
        return this.createCaptureRequest(templateType);
    };
});

// --- Hook 37: Ambient Audio Recording ---
Java.perform(function() {
    var AudioRecord = Java.use("android.media.AudioRecord");
    AudioRecord.startRecording.implementation = function() {
        console.log("[RAT-AUDIO] startRecording() — capture active");
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("Service") !== -1 && stack.indexOf("Activity") === -1) {
            console.log("  [CRITICAL] Background audio recording — ambient capture");
        }
        return this.startRecording();
    };
});

// --- Hook 38: Screen Streaming ---
Java.perform(function() {
    var MediaProjection = Java.use("android.media.projection.MediaProjection");
    MediaProjection.createVirtualDisplay.overload(
        'java.lang.String', 'int', 'int', 'int', 'int',
        'android.view.Surface', 'android.hardware.display.VirtualDisplay$Callback',
        'android.os.Handler'
    ).implementation = function(name, width, height, dpi, flags, surface, callback, handler) {
        console.log("[RAT-SCREEN] createVirtualDisplay: " + width + "x" + height);
        console.log("  [CRITICAL] Screen capture — VNC/streaming");
        return this.createVirtualDisplay(name, width, height, dpi, flags, surface, callback, handler);
    };
});

// --- Hook 39: TOTP Authenticator Scraping ---
Java.perform(function() {
    var authPkgs = [
        "com.google.android.apps.authenticator2", "com.azure.authenticator",
        "com.authy.authy", "com.beemdevelopment.aegis"
    ];
    try {
        var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        var origGetText = ANI.getText;
        ANI.getText.implementation = function() {
            var text = origGetText.call(this);
            if (text !== null) {
                var pkg = this.getPackageName();
                var pkgStr = pkg ? pkg.toString() : "";
                var textStr = text.toString();
                var isAuth = authPkgs.some(function(p) { return pkgStr.indexOf(p) !== -1; });
                if (isAuth && textStr.match(/^\d{6,8}$/)) {
                    console.log("[RAT-TOTP] Code scraped from " + pkgStr + ": " + textStr);
                }
            }
            return text;
        };
    } catch(e) {}
});

// --- Hook 40: Call Forwarding USSD ---
Java.perform(function() {
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.sendUssdRequest.overload(
            'java.lang.String',
            'android.telephony.TelephonyManager$UssdResponseCallback',
            'android.os.Handler'
        ).implementation = function(ussd, callback, handler) {
            console.log("[RAT-USSD] sendUssdRequest: " + ussd);
            if (ussd.indexOf("*21*") !== -1 || ussd.indexOf("*61*") !== -1 ||
                ussd.indexOf("*67*") !== -1) {
                console.log("  [CRITICAL] Call forwarding — FakeCall pattern");
            }
            return this.sendUssdRequest(ussd, callback, handler);
        };
    } catch(e) {}
});

// --- Hook 41: Touch/Keylogging ---
Java.perform(function() {
    var touchRate = 0;
    var lastTouchCheck = 0;
    try {
        var View = Java.use("android.view.View");
        View.dispatchTouchEvent.implementation = function(event) {
            touchRate++;
            var now = Date.now();
            if (now - lastTouchCheck >= 1000) {
                if (touchRate > 5) {
                    console.log("[RAT-TOUCH] High-freq logging: " + touchRate + " events/sec");
                }
                touchRate = 0;
                lastTouchCheck = now;
            }
            return this.dispatchTouchEvent(event);
        };
    } catch(e) {}
});

// --- Hook 42: Notification Suppression ---
Java.perform(function() {
    var NotificationManager = Java.use("android.app.NotificationManager");
    NotificationManager.cancelAll.implementation = function() {
        console.log("[RAT-NOTIF] cancelAll() — mass suppression");
        return this.cancelAll();
    };
});

// --- Hook 43: Contact Injection ---
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.applyBatch.overload(
        'java.lang.String', 'java.util.ArrayList'
    ).implementation = function(authority, ops) {
        if (authority.indexOf("contacts") !== -1) {
            console.log("[RAT-CONTACTS] applyBatch: " + ops.size() + " ops");
            if (ops.size() > 3) {
                console.log("  [ALERT] Bulk contact manipulation — Crocodilus pattern");
            }
        }
        return this.applyBatch(authority, ops);
    };
});

// --- Hook 44: Remote Shell ---
Java.perform(function() {
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function() {
        var cmd = this.command();
        var cmdStr = "";
        for (var i = 0; i < cmd.size(); i++) cmdStr += cmd.get(i) + " ";
        console.log("[RAT-SHELL] ProcessBuilder: " + cmdStr.trim());
        return this.start();
    };
});

// --- Hook 45: Security App Removal ---
Java.perform(function() {
    var avPkgs = ["com.avast", "com.kaspersky", "com.bitdefender",
        "org.malwarebytes", "com.symantec", "com.eset"];
    var PackageManager = Java.use("android.content.pm.PackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int')
        .implementation = function(pkg, flags) {
        var isAv = avPkgs.some(function(av) { return pkg.indexOf(av) !== -1; });
        if (isAv) console.log("[RAT-AVKILL] AV query: " + pkg);
        return this.getPackageInfo(pkg, flags);
    };
});

// --- Hook 46: Factory Reset ---
Java.perform(function() {
    try {
        var DPM = Java.use("android.app.admin.DevicePolicyManager");
        DPM.wipeData.overload('int').implementation = function(flags) {
            console.log("[RAT-WIPE] wipeData(flags=" + flags + ")");
            console.log("  [CRITICAL] Remote factory reset — BRATA pattern");
            console.log("  [BLOCKED] Wipe blocked by monitor");
        };
    } catch(e) {}
});

// --- Hook 47: Geolocation Tracking ---
Java.perform(function() {
    var LocationManager = Java.use("android.location.LocationManager");
    LocationManager.requestLocationUpdates.overload(
        'java.lang.String', 'long', 'float', 'android.location.LocationListener'
    ).implementation = function(provider, minTime, minDist, listener) {
        console.log("[RAT-GEO] requestLocationUpdates: " + provider + " @" + minTime + "ms");
        if (minTime < 60000) console.log("  [ALERT] High-frequency tracking");
        return this.requestLocationUpdates(provider, minTime, minDist, listener);
    };
});

// ================================================================
console.log("[TAKOPII] Master monitor loaded — 48 hooks active");
console.log("[TAKOPII] Sections: Core(10) + Evasion(7) + Frontier(12) + Deep(7) + RAT(12)");
// ================================================================
