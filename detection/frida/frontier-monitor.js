/**
 * Takopii — Frontier 2025-2026 Technique Monitors
 *
 * All frontier module detection hooks for advanced banker-malware
 * primitives emerging in 2025-2026: TYPE_ACCESSIBILITY_OVERLAY,
 * hidden VNC, NFC relay, residential proxy, behavior mimicry,
 * SSO hijacking, TEE offload, Yamux multiplexing, per-build
 * obfuscation, persistence layer, spread modules, and more.
 *
 * Hook 18: A11yOverlay2032 intercept
 * Hook 19: HiddenVnc frame rate monitor
 * Hook 20: NfcRelay APDU monitor
 * Hook 21: ResidentialProxy session monitor
 * Hook 22: BehaviorMimicry timing analysis
 * Hook 23: SsoHijacker intercept
 * Hook 24: TeeOffload key + crypto monitor
 * Hook 25: YamuxProxy stream monitor
 * Hook 26: PerBuildObfuscation seed capture
 * Hook 27: EarlyInitProvider execution order
 * Hook 28: ContactHarvester monitor
 * Hook 29: SmsWorm rate-limited spread monitor
 * Hook 35: UpdateChannel response capture
 *
 * Usage: frida -U -l frontier-monitor.js -f com.target.package
 */

// ============================================================
// Hook 18: A11yOverlay2032 Intercept
// ============================================================
Java.perform(function() {
    var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");

    WindowManagerImpl.addView.implementation = function(view, params) {
        var lp = Java.cast(params, Java.use("android.view.WindowManager$LayoutParams"));
        var type = lp.type.value;

        if (type === 2032) {
            console.log("[CRITICAL] TYPE_ACCESSIBILITY_OVERLAY (2032) created!");
            console.log("  Package: " + Java.use("android.app.ActivityThread")
                .currentApplication().getApplicationContext().getPackageName());
            console.log("  Flags: 0x" + lp.flags.value.toString(16));
            console.log("  Size: " + lp.width.value + "x" + lp.height.value);
            console.log("  [ALERT] No SYSTEM_ALERT_WINDOW permission needed — " +
                "A11y grant IS the overlay permission");
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.addView(view, params);
    };
});

// ============================================================
// Hook 19: HiddenVnc Frame Rate Monitor
// ============================================================
Java.perform(function() {
    var ImageReader = Java.use("android.media.ImageReader");
    var frameCount = 0;
    var lastFrameTime = 0;
    var frameTimes = [];

    ImageReader.acquireLatestImage.implementation = function() {
        frameCount++;
        var now = Date.now();
        if (lastFrameTime > 0) {
            var delta = now - lastFrameTime;
            frameTimes.push(delta);
            if (frameTimes.length > 10) frameTimes.shift();

            var avgFps = 1000 / (frameTimes.reduce(function(a, b) {
                return a + b;
            }) / frameTimes.length);

            if (frameCount % 10 === 0) {
                console.log("[VNC] Frame #" + frameCount +
                    " | avg FPS: " + avgFps.toFixed(1) +
                    " | resolution: " + this.getWidth() + "x" + this.getHeight());
            }
        }
        lastFrameTime = now;

        var image = this.acquireLatestImage();
        if (image !== null) {
            console.log("[VNC] Frame acquired: " + image.getWidth() + "x" +
                image.getHeight() + " format=" + image.getFormat());
        }
        return image;
    };

    // Monitor VirtualDisplay creation
    var DisplayManager = Java.use("android.hardware.display.DisplayManager");
    DisplayManager.createVirtualDisplay.overload(
        'java.lang.String', 'int', 'int', 'int',
        'android.view.Surface', 'int'
    ).implementation = function(name, width, height, dpi, surface, flags) {
        console.log("[VNC] createVirtualDisplay: " + name +
            " " + width + "x" + height + " @" + dpi + "dpi");
        return this.createVirtualDisplay(name, width, height, dpi, surface, flags);
    };
});

// ============================================================
// Hook 20: NfcRelay APDU Monitor
// ============================================================
Java.perform(function() {
    try {
        var NfcRelayService = Java.use("com.docreader.lite.stealer.frontier.NfcRelayService");

        NfcRelayService.processCommandApdu.implementation = function(apdu, extras) {
            var hexApdu = "";
            for (var i = 0; i < apdu.length; i++) {
                hexApdu += ("0" + (apdu[i] & 0xFF).toString(16)).slice(-2) + " ";
            }
            console.log("[NFC-RELAY] processCommandApdu: " + hexApdu.trim());

            // Detect SELECT PPSE (payment)
            if (apdu.length >= 5 && apdu[0] === 0x00 &&
                (apdu[1] & 0xFF) === 0xA4 && apdu[2] === 0x04) {
                console.log("  [CRITICAL] SELECT command — payment AID selection");
                var aid = "";
                for (var j = 5; j < apdu.length - 1; j++) {
                    aid += String.fromCharCode(apdu[j] & 0xFF);
                }
                console.log("  AID: " + aid);
                if (aid.indexOf("2PAY.SYS.DDF01") !== -1) {
                    console.log("  [ALERT] SELECT_PPSE — NFC payment relay detected!");
                }
            }

            var response = this.processCommandApdu(apdu, extras);
            if (response) {
                var hexResp = "";
                for (var k = 0; k < response.length; k++) {
                    hexResp += ("0" + (response[k] & 0xFF).toString(16)).slice(-2) + " ";
                }
                console.log("[NFC-RELAY] Response: " + hexResp.trim());
            }
            return response;
        };
    } catch(e) {
        console.log("[NFC-RELAY] Service not loaded: " + e);
    }

    // Also monitor relay socket connection
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
        var addrStr = addr.toString();
        if (addrStr.indexOf("9999") !== -1) {
            console.log("[NFC-RELAY] Relay connection to: " + addrStr);
        }
        return this.connect(addr, timeout);
    };
});

// ============================================================
// Hook 21: ResidentialProxy Session Monitor
// ============================================================
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
        console.log("  Local port: " + socket.getLocalPort());
        return socket;
    };

    // Monitor SOCKS5 handshake bytes
    var InputStream = Java.use("java.io.InputStream");
    InputStream.read.overload('[B').implementation = function(buf) {
        var n = this.read(buf);
        if (n > 0 && (buf[0] & 0xFF) === 0x05) {
            // SOCKS5 version byte
            console.log("[PROXY] SOCKS5 handshake detected (version=5, nmethods=" +
                (buf[1] & 0xFF) + ")");
        }
        return n;
    };
});

// ============================================================
// Hook 22: BehaviorMimicry Timing Analysis
// ============================================================
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    var timingSamples = [];

    AccessibilityService.dispatchGesture.overload(
        'android.accessibilityservice.GestureDescription',
        'android.accessibilityservice.AccessibilityService$GestureResultCallback',
        'android.os.Handler'
    ).implementation = function(gesture, callback, handler) {
        var now = Date.now();
        timingSamples.push(now);

        if (timingSamples.length > 1) {
            var delta = timingSamples[timingSamples.length - 1] -
                timingSamples[timingSamples.length - 2];
            console.log("[MIMICRY] Gesture delta: " + delta + "ms");

            // Statistical analysis after 10+ samples
            if (timingSamples.length >= 10) {
                var deltas = [];
                for (var i = 1; i < timingSamples.length; i++) {
                    deltas.push(timingSamples[i] - timingSamples[i - 1]);
                }

                var mean = deltas.reduce(function(a, b) { return a + b; }) / deltas.length;
                var variance = deltas.reduce(function(a, b) {
                    return a + (b - mean) * (b - mean);
                }, 0) / deltas.length;
                var stddev = Math.sqrt(variance);
                var cv = stddev / mean; // coefficient of variation

                console.log("[MIMICRY] === Timing Analysis (n=" + deltas.length + ") ===");
                console.log("  Mean: " + mean.toFixed(0) + "ms");
                console.log("  StdDev: " + stddev.toFixed(0) + "ms");
                console.log("  CV: " + cv.toFixed(3));

                // Uniform(300,3000) has CV ~0.577 and range [300,3000]
                var min = Math.min.apply(null, deltas);
                var max = Math.max.apply(null, deltas);
                console.log("  Range: [" + min + ", " + max + "]");

                if (cv > 0.5 && cv < 0.65 && min >= 250 && max <= 3100) {
                    console.log("  [DETECTED] Herodotus original: uniform(300,3000)");
                } else if (cv > 0.3 && cv < 0.5) {
                    console.log("  [SUSPECT] Log-normal distribution — improved variant");
                } else if (cv < 0.1) {
                    console.log("  [DETECTED] Fixed interval — naive automation");
                }
            }
        }
        return this.dispatchGesture(gesture, callback, handler);
    };

    // Also hook Random to detect jitter source
    var Random = Java.use("java.util.Random");
    Random.nextLong.implementation = function() {
        var result = this.nextLong();
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("BehaviorMimicry") !== -1 || stack.indexOf("Jitter") !== -1 ||
            stack.indexOf("Gesture") !== -1) {
            console.log("[MIMICRY] Random.nextLong() for jitter: " + result);
        }
        return result;
    };
});

// ============================================================
// Hook 23: SsoHijacker Intercept
// ============================================================
Java.perform(function() {
    var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    var ssoApps = [
        "com.azure.authenticator", "com.okta.android",
        "com.duosecurity.duomobile", "com.google.android.apps.authenticator2",
        "com.authy.authy"
    ];

    ANI.performAction.overload('int').implementation = function(action) {
        if (action === 16) { // ACTION_CLICK = 16
            var pkg = this.getPackageName();
            var pkgStr = pkg ? pkg.toString() : "";
            var text = this.getText();
            var textStr = text ? text.toString().toLowerCase() : "";

            // Check if click is on SSO app
            var isSsoApp = ssoApps.some(function(sso) {
                return pkgStr.indexOf(sso) !== -1;
            });

            var isApproveButton = ["approve", "allow", "confirm", "verify",
                "accept", "it's me", "onayla", "aprobar"]
                .some(function(p) { return textStr.indexOf(p) !== -1; });

            if (isSsoApp && isApproveButton) {
                console.log("[SSO-HIJACK] AUTO-APPROVE detected!");
                console.log("  SSO app: " + pkgStr);
                console.log("  Button text: " + textStr);
                console.log("  [CRITICAL] Vespertine MFA bypass — sub-500ms approval");
            }
        }
        return this.performAction(action);
    };
});

// ============================================================
// Hook 24: TeeOffload Key + Crypto Monitor
// ============================================================
Java.perform(function() {
    // Monitor key generation
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

    // Monitor Cipher operations — capture plaintext BEFORE TEE encrypt
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var mode = this.getOpmode(); // 1=ENCRYPT, 2=DECRYPT
        var algo = this.getAlgorithm();

        if (algo.indexOf("AES") !== -1 || algo.indexOf("GCM") !== -1) {
            if (mode === 1) {
                // ENCRYPT: input is plaintext — capture before TEE encrypts
                var plaintext = "";
                try {
                    plaintext = Java.use("java.lang.String").$new(input);
                } catch(e) {
                    plaintext = "<binary " + input.length + " bytes>";
                }
                console.log("[TEE] Cipher.doFinal ENCRYPT:");
                console.log("  Algorithm: " + algo);
                console.log("  Plaintext: " + plaintext.substring(0, 200));
                console.log("  [CAPTURE] Plaintext captured before TEE encryption");
            }

            var result = this.doFinal(input);

            if (mode === 2) {
                // DECRYPT: result is plaintext — capture after TEE decrypts
                var decrypted = "";
                try {
                    decrypted = Java.use("java.lang.String").$new(result);
                } catch(e) {
                    decrypted = "<binary " + result.length + " bytes>";
                }
                console.log("[TEE] Cipher.doFinal DECRYPT:");
                console.log("  Algorithm: " + algo);
                console.log("  Decrypted: " + decrypted.substring(0, 200));
            }
            return result;
        }
        return this.doFinal(input);
    };

    // Monitor KeyStore key alias creation
    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
        if (type === "AndroidKeyStore") {
            console.log("[TEE] KeyStore.getInstance('AndroidKeyStore')");
        }
        return this.getInstance(type);
    };
});

// ============================================================
// Hook 25: YamuxProxy Stream Monitor
// ============================================================
Java.perform(function() {
    // Monitor socket output for Yamux frames
    var OutputStream = Java.use("java.io.OutputStream");
    OutputStream.write.overload('[B', 'int', 'int').implementation = function(buf, off, len) {
        // Check for Yamux header pattern
        if (len >= 12 && (buf[off] & 0xFF) === 0x00) { // Version 0
            var type = buf[off + 1] & 0xFF;
            var flags = ((buf[off + 2] & 0xFF) << 8) | (buf[off + 3] & 0xFF);
            var streamId = ((buf[off + 4] & 0xFF) << 24) | ((buf[off + 5] & 0xFF) << 16) |
                ((buf[off + 6] & 0xFF) << 8) | (buf[off + 7] & 0xFF);
            var payloadLen = ((buf[off + 8] & 0xFF) << 24) | ((buf[off + 9] & 0xFF) << 16) |
                ((buf[off + 10] & 0xFF) << 8) | (buf[off + 11] & 0xFF);

            var types = {0: "DATA", 1: "WINDOW_UPDATE", 2: "PING", 3: "GO_AWAY"};
            var flagNames = [];
            if (flags & 1) flagNames.push("SYN");
            if (flags & 2) flagNames.push("ACK");
            if (flags & 4) flagNames.push("FIN");
            if (flags & 8) flagNames.push("RST");

            console.log("[YAMUX] Frame: type=" + (types[type] || type) +
                " flags=[" + flagNames.join(",") + "]" +
                " stream=" + streamId +
                " len=" + payloadLen);

            if (type === 0 && payloadLen > 0) {
                console.log("  [DATA] " + payloadLen + " bytes on stream " + streamId);
            }
            if (flags & 1) {
                console.log("  [NEW STREAM] Stream " + streamId + " opened");
            }
        }
        return this.write(buf, off, len);
    };
});

// ============================================================
// Hook 26: PerBuildObfuscation Seed Capture
// ============================================================
Java.perform(function() {
    // Hook SecureRandom to capture build seed
    var SecureRandom = Java.use("java.security.SecureRandom");
    SecureRandom.$init.overload('[B').implementation = function(seed) {
        console.log("[PERBUILD] SecureRandom seeded with " + seed.length + " bytes");
        var hex = "";
        for (var i = 0; i < seed.length; i++) {
            hex += ("0" + (seed[i] & 0xFF).toString(16)).slice(-2);
        }
        console.log("  Seed hex: " + hex);

        // Reconstruct the seed as long value
        if (seed.length === 8) {
            var value = 0;
            for (var j = 0; j < 8; j++) {
                value = value * 256 + (seed[j] & 0xFF);
            }
            console.log("  BUILD_SEED (long): " + value);
            console.log("  [CAPTURE] With this seed, defender can reconstruct xorKey, " +
                "rotAmount, addKey — full decode pipeline");
        }
        return this.$init(seed);
    };

    // Hook encode/decode methods to see transformations
    try {
        var PBO = Java.use("com.docreader.lite.stealer.frontier.PerBuildObfuscation");

        PBO.encode.implementation = function(plaintext) {
            console.log("[PERBUILD] encode('" + plaintext.substring(0, 50) + "')");
            var result = this.encode(plaintext);
            console.log("  Encoded: " + result.length + " bytes");
            return result;
        };

        PBO.decode.implementation = function(encoded) {
            var result = this.decode(encoded);
            console.log("[PERBUILD] decode -> '" + result.substring(0, 100) + "'");
            return result;
        };
    } catch(e) {}
});

// ============================================================
// Hook 27: EarlyInitProvider Execution Order Monitor
// ============================================================
Java.perform(function() {
    var ContentProvider = Java.use("android.content.ContentProvider");
    ContentProvider.onCreate.implementation = function() {
        var className = this.getClass().getName();
        console.log("[PERSISTENCE] ContentProvider.onCreate: " + className);
        console.log("  Timestamp: " + Date.now());

        if (className.indexOf("EarlyInit") !== -1 || className.indexOf("Init") !== -1) {
            console.log("  [ALERT] Init-hook ContentProvider — pre-Application execution");
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        return this.onCreate();
    };

    var Application = Java.use("android.app.Application");
    Application.onCreate.implementation = function() {
        console.log("[PERSISTENCE] Application.onCreate at " + Date.now());
        console.log("  (ContentProvider.onCreate already ran — compare timestamps)");
        return this.onCreate();
    };
});

// ============================================================
// Hook 28: ContactHarvester Monitor
// ============================================================
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
        '[Ljava.lang.String;', 'java.lang.String'
    ).implementation = function(uri, proj, sel, selArgs, sort) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("contacts") !== -1 || uriStr.indexOf("phone") !== -1 ||
            uriStr.indexOf("ContactsContract") !== -1) {
            var callerPkg = Java.use("android.app.ActivityThread")
                .currentApplication().getApplicationContext().getPackageName();
            console.log("[HARVEST] Contact query from: " + callerPkg);
            console.log("  URI: " + uriStr);
            console.log("  Projection: " + (proj ? proj.join(", ") : "all"));
            console.log("  Sort: " + sort);

            // Count results to detect bulk harvest
            var cursor = this.query(uri, proj, sel, selArgs, sort);
            if (cursor !== null) {
                var count = cursor.getCount();
                console.log("  Results: " + count + " contacts");
                if (count > 10) {
                    console.log("  [ALERT] Bulk contact harvest — " + count +
                        " contacts queried by non-contacts app");
                }
            }
            return cursor;
        }
        return this.query(uri, proj, sel, selArgs, sort);
    };
});

// ============================================================
// Hook 29: SmsWorm Rate-Limited Spread Monitor
// ============================================================
Java.perform(function() {
    var smsSendTimes = [];
    var smsDestinations = [];

    // Hook SmsManager.sendTextMessage
    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.overload(
        'java.lang.String', 'java.lang.String', 'java.lang.String',
        'android.app.PendingIntent', 'android.app.PendingIntent'
    ).implementation = function(dest, sc, body, sentIntent, deliveryIntent) {
        var now = Date.now();
        smsSendTimes.push(now);
        smsDestinations.push(dest);

        console.log("[SMS-WORM] sendTextMessage:");
        console.log("  Destination: " + dest);
        console.log("  Body: " + body.substring(0, 100));
        console.log("  Total sent this session: " + smsSendTimes.length);

        // Rate analysis
        if (smsSendTimes.length > 1) {
            var delta = (now - smsSendTimes[smsSendTimes.length - 2]) / 1000;
            console.log("  Time since last: " + delta.toFixed(1) + "s");

            if (delta >= 25 && delta <= 65) {
                console.log("  [ALERT] Rate-limited spreading pattern (30-60s interval)");
            }
        }

        // Unique destination analysis
        var unique = [];
        smsDestinations.forEach(function(d) {
            if (unique.indexOf(d) === -1) unique.push(d);
        });
        if (unique.length > 5) {
            console.log("  [CRITICAL] SMS sent to " + unique.length +
                " unique recipients — worm spreading!");
        }

        // URL detection in body
        if (body.match(/https?:\/\/[^\s]+/)) {
            console.log("  [ALERT] URL in SMS body — install-link lure");
        }

        return this.sendTextMessage(dest, sc, body, sentIntent, deliveryIntent);
    };

    // Also hook reflection-based SMS sending (ReflectionHider.sendSms)
    var Method = Java.use("java.lang.reflect.Method");
    Method.invoke.implementation = function(obj, args) {
        var methodName = this.getName();
        if (methodName === "sendTextMessage" && args && args.length >= 3) {
            console.log("[SMS-WORM-REFLECT] SMS via reflection to: " + args[0]);
        }
        return this.invoke(obj, args);
    };
});

// ============================================================
// Hook 35: UpdateChannel Response Capture
// ============================================================
Java.perform(function() {
    // Hook HTTP response body reading for update endpoint
    var BufferedReader = Java.use("java.io.BufferedReader");
    var InputStreamReader = Java.use("java.io.InputStreamReader");

    // Track active URL for context
    var activeUrl = "";
    var URL = Java.use("java.net.URL");
    URL.$init.overload('java.lang.String').implementation = function(url) {
        if (url.indexOf("/api/v1/update") !== -1 || url.indexOf("/api/v1/config") !== -1 ||
            url.indexOf("/api/v1/commands") !== -1) {
            activeUrl = url;
            console.log("[UPDATE-CH] Config/update request: " + url);
        }
        return this.$init(url);
    };

    // Capture JSON response parsing
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.$init.overload('java.lang.String').implementation = function(json) {
            if (activeUrl.indexOf("/api/v1/") !== -1) {
                console.log("[UPDATE-CH] JSON response parsed:");
                var jsonStr = json.length > 500 ? json.substring(0, 500) + "..." : json;
                console.log("  Body: " + jsonStr);

                // Parse known UpdateConfig fields
                try {
                    var obj = this.$init(json);
                    if (obj.has("c2_host") || obj.has("newC2Host")) {
                        console.log("  [C2-ROTATE] New C2 host: " +
                            (obj.optString("c2_host") || obj.optString("newC2Host")));
                    }
                    if (obj.has("c2_port") || obj.has("newC2Port")) {
                        console.log("  [C2-ROTATE] New C2 port: " +
                            (obj.optInt("c2_port") || obj.optInt("newC2Port")));
                    }
                    if (obj.has("targets") || obj.has("newTargets")) {
                        console.log("  [TARGETS] Target list update: " +
                            (obj.optString("targets") || obj.optString("newTargets")));
                    }
                    if (obj.has("payload_url") || obj.has("newPayloadUrl")) {
                        console.log("  [PAYLOAD] New payload URL: " +
                            (obj.optString("payload_url") || obj.optString("newPayloadUrl")));
                    }
                    if (obj.has("kill") || obj.has("killBotIds")) {
                        console.log("  [KILL] Kill switch for bot IDs: " +
                            (obj.optString("kill") || obj.optString("killBotIds")));
                    }
                    return obj;
                } catch(e) {}
            }
            return this.$init(json);
        };
    } catch(e) {}

    // Monitor OkHttp responses (overlay-banker uses OkHttp)
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
