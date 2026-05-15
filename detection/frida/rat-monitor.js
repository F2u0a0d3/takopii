/**
 * Takopii Detection Corpus — RAT Capabilities Monitor
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 *
 * Description:
 *   Frida hooks for RAT-class capabilities added in v0.1.0 expansion:
 *   Silent camera, ambient audio, screen streaming, TOTP scraping,
 *   touch/keylogging, call forwarding, notification suppression,
 *   contact injection, remote shell, AV removal, factory reset,
 *   geolocation tracking.
 *
 *   Family references: Brokewell, Crocodilus, FakeCall, TrickMo,
 *   ToxicPanda, Cerberus, BRATA, SpyNote
 *
 * Usage: frida -U -l rat-monitor.js -f com.target.package
 */

// ================================================================
//  RAT HOOK 1: Camera2 Silent Capture Monitor
//  Families: Brokewell, SpyNote, Cerberus
// ================================================================
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
        console.log("  Stack: " + Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
        return this.openCamera(cameraId, callback, handler);
    };

    var CameraDevice = Java.use("android.hardware.camera2.CameraDevice");
    CameraDevice.createCaptureRequest.implementation = function(templateType) {
        var templates = {1: "PREVIEW", 2: "STILL_CAPTURE", 3: "RECORD"};
        console.log("[RAT-CAMERA] createCaptureRequest: " +
            (templates[templateType] || "TEMPLATE_" + templateType));
        if (templateType === 2) {
            console.log("  [ALERT] STILL_CAPTURE without visible preview — silent photo");
        }
        return this.createCaptureRequest(templateType);
    };

    try {
        var CaptureRequest = Java.use("android.hardware.camera2.CaptureRequest$Builder");
        CaptureRequest.set.implementation = function(key, value) {
            var keyName = key.getName();
            if (keyName === "android.flash.mode") {
                var intVal = Java.cast(value, Java.use("java.lang.Integer")).intValue();
                if (intVal === 0) {
                    console.log("[RAT-CAMERA] Flash disabled — stealth capture");
                }
            }
            return this.set(key, value);
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 2: Ambient Audio Recording Monitor
//  Families: Brokewell, Cerberus, SpyNote
// ================================================================
Java.perform(function() {
    var AudioRecord = Java.use("android.media.AudioRecord");
    AudioRecord.$init.overload('int', 'int', 'int', 'int', 'int')
        .implementation = function(audioSource, sampleRate, channelConfig, audioFormat, bufferSize) {
        var sources = {0: "DEFAULT", 1: "MIC", 2: "VOICE_UPLINK",
            3: "VOICE_DOWNLINK", 4: "VOICE_CALL", 5: "CAMCORDER", 7: "VOICE_RECOGNITION"};
        console.log("[RAT-AUDIO] AudioRecord init:");
        console.log("  Source: " + (sources[audioSource] || audioSource));
        console.log("  SampleRate: " + sampleRate + "Hz");
        console.log("  BufferSize: " + bufferSize + " bytes");
        if (audioSource === 1) {
            console.log("  [ALERT] MIC source — ambient recording capability");
        }
        if (audioSource === 4) {
            console.log("  [CRITICAL] VOICE_CALL source — call recording");
        }
        return this.$init(audioSource, sampleRate, channelConfig, audioFormat, bufferSize);
    };

    AudioRecord.startRecording.implementation = function() {
        console.log("[RAT-AUDIO] startRecording() — audio capture active");
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("Service") !== -1 && stack.indexOf("Activity") === -1) {
            console.log("  [CRITICAL] Recording from background service — ambient recording");
        }
        return this.startRecording();
    };

    AudioRecord.stop.implementation = function() {
        console.log("[RAT-AUDIO] stop() — audio capture stopped");
        return this.stop();
    };
});

// ================================================================
//  RAT HOOK 3: Screen Streaming / MediaProjection Monitor
//  Families: Brokewell, Klopatra, ToxicPanda
// ================================================================
Java.perform(function() {
    var MediaProjection = Java.use("android.media.projection.MediaProjection");
    MediaProjection.createVirtualDisplay.overload(
        'java.lang.String', 'int', 'int', 'int', 'int',
        'android.view.Surface', 'android.hardware.display.VirtualDisplay$Callback',
        'android.os.Handler'
    ).implementation = function(name, width, height, dpi, flags, surface, callback, handler) {
        console.log("[RAT-SCREEN] createVirtualDisplay:");
        console.log("  Name: " + name);
        console.log("  Resolution: " + width + "x" + height + " @" + dpi + "dpi");
        console.log("  [CRITICAL] Screen capture initiated — VNC/streaming capability");
        return this.createVirtualDisplay(name, width, height, dpi, flags, surface, callback, handler);
    };

    // WebSocket frame send detection for streaming
    try {
        var WebSocket = Java.use("okhttp3.WebSocket");
        // Monitor send for image frames
        var RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");
        var wsFrameCount = 0;
        var lastWsTime = 0;

        RealWebSocket.send.overload('okio.ByteString').implementation = function(data) {
            wsFrameCount++;
            var now = Date.now();
            if (now - lastWsTime > 5000) {
                if (wsFrameCount > 10) {
                    console.log("[RAT-SCREEN] WebSocket burst: " + wsFrameCount +
                        " frames in 5s — screen streaming pattern");
                }
                wsFrameCount = 0;
            }
            lastWsTime = now;
            return this.send(data);
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 4: TOTP Authenticator Scraping Monitor
//  Family: Crocodilus (first commodity banker to target Google Authenticator)
// ================================================================
Java.perform(function() {
    var authenticatorPkgs = [
        "com.google.android.apps.authenticator2",
        "com.azure.authenticator",
        "com.authy.authy",
        "com.beemdevelopment.aegis",
        "org.shadowice.flocke.andotp"
    ];

    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    // Wrap existing onAccessibilityEvent if not already wrapped
    try {
        var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        ANI.getText.implementation = function() {
            var text = this.getText();
            if (text !== null) {
                var pkg = this.getPackageName();
                var pkgStr = pkg ? pkg.toString() : "";
                var textStr = text.toString();

                var isAuthApp = authenticatorPkgs.some(function(p) {
                    return pkgStr.indexOf(p) !== -1;
                });

                if (isAuthApp && textStr.match(/^\d{6,8}$/)) {
                    console.log("[RAT-TOTP] TOTP code captured from " + pkgStr + ": " + textStr);
                    console.log("  [CRITICAL] Crocodilus-class authenticator scraping");
                }
            }
            return text;
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 5: Touch/Keylogging Monitor
//  Families: Brokewell, TrickMo (PIN pad capture)
// ================================================================
Java.perform(function() {
    var touchEvents = [];
    var bankingPackages = ["bank", "finance", "wallet", "pay", "money"];

    var AccessibilityEvent = Java.use("android.view.accessibility.AccessibilityEvent");
    // Monitor high-frequency event capture
    var eventCount = 0;
    var lastEventTime = 0;

    try {
        var MotionEvent = Java.use("android.view.MotionEvent");
        MotionEvent.obtain.overload('float', 'float', 'int', 'int')
            .implementation = function(x, y, action, metaState) {
            // Synthetic touch events from non-input source
            console.log("[RAT-TOUCH] Synthetic MotionEvent: x=" + x + " y=" + y +
                " action=" + action);
            return this.obtain(x, y, action, metaState);
        };
    } catch(e) {}

    // Monitor InputEvent dispatch frequency
    try {
        var View = Java.use("android.view.View");
        View.dispatchTouchEvent.implementation = function(event) {
            eventCount++;
            var now = Date.now();
            if (now - lastEventTime >= 1000) {
                if (eventCount > 5) {
                    console.log("[RAT-TOUCH] High-frequency touch logging: " +
                        eventCount + " events/sec");
                }
                eventCount = 0;
                lastEventTime = now;
            }
            return this.dispatchTouchEvent(event);
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 6: Call Forwarding / USSD Monitor
//  Family: FakeCall (Zimperium 2025)
// ================================================================
Java.perform(function() {
    // USSD code execution
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.sendUssdRequest.overload(
            'java.lang.String',
            'android.telephony.TelephonyManager$UssdResponseCallback',
            'android.os.Handler'
        ).implementation = function(ussdRequest, callback, handler) {
            console.log("[RAT-USSD] sendUssdRequest: " + ussdRequest);
            if (ussdRequest.indexOf("*21*") !== -1 || ussdRequest.indexOf("*61*") !== -1 ||
                ussdRequest.indexOf("*67*") !== -1 || ussdRequest.indexOf("*62*") !== -1) {
                console.log("  [CRITICAL] Call forwarding USSD — FakeCall pattern");
                console.log("  Forwarding to: " + ussdRequest.replace(/\*\d+\*/, "").replace(/#$/, ""));
            }
            if (ussdRequest.indexOf("##21#") !== -1) {
                console.log("  [INFO] Call forwarding cancel code");
            }
            return this.sendUssdRequest(ussdRequest, callback, handler);
        };
    } catch(e) {}

    // Intent-based call interception
    try {
        var Intent = Java.use("android.content.Intent");
        Intent.setAction.implementation = function(action) {
            if (action === "android.intent.action.CALL" ||
                action === "android.intent.action.CALL_PRIVILEGED") {
                var data = this.getData();
                if (data !== null) {
                    var uri = data.toString();
                    if (uri.indexOf("tel:") !== -1 && uri.match(/\*\d+\*/)) {
                        console.log("[RAT-USSD] Call intent with USSD code: " + uri);
                    }
                }
            }
            return this.setAction(action);
        };
    } catch(e) {}

    // RoleManager default dialer takeover
    try {
        var RoleManager = Java.use("android.app.role.RoleManager");
        RoleManager.isRoleHeld.implementation = function(roleName) {
            var result = this.isRoleHeld(roleName);
            if (roleName === "android.app.role.DIALER") {
                console.log("[RAT-USSD] isRoleHeld(DIALER) = " + result);
                if (result) {
                    console.log("  [CRITICAL] App is default dialer — can intercept outgoing calls");
                }
            }
            return result;
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 7: Notification Suppression Monitor
//  Families: TrickMo, SOVA
// ================================================================
Java.perform(function() {
    var NotificationManager = Java.use("android.app.NotificationManager");
    NotificationManager.cancel.overload('int').implementation = function(id) {
        console.log("[RAT-NOTIF] NotificationManager.cancel(id=" + id + ")");
        return this.cancel(id);
    };

    NotificationManager.cancel.overload('java.lang.String', 'int')
        .implementation = function(tag, id) {
        console.log("[RAT-NOTIF] NotificationManager.cancel(tag=" + tag + ", id=" + id + ")");
        return this.cancel(tag, id);
    };

    NotificationManager.cancelAll.implementation = function() {
        console.log("[RAT-NOTIF] cancelAll() — all notifications suppressed");
        console.log("  [ALERT] Mass notification suppression — fraud concealment pattern");
        return this.cancelAll();
    };

    // NLS-based notification removal
    try {
        var NLS = Java.use("android.service.notification.NotificationListenerService");
        NLS.cancelNotification.overload('java.lang.String')
            .implementation = function(key) {
            console.log("[RAT-NOTIF] NLS.cancelNotification: " + key);
            if (key.indexOf("bank") !== -1 || key.indexOf("finance") !== -1) {
                console.log("  [CRITICAL] Banking notification suppressed during fraud");
            }
            return this.cancelNotification(key);
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 8: Contact Injection/Replacement Monitor
//  Family: Crocodilus (June 2025)
// ================================================================
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.applyBatch.overload(
        'java.lang.String', 'java.util.ArrayList'
    ).implementation = function(authority, operations) {
        if (authority.indexOf("contacts") !== -1 || authority.indexOf("com.android.contacts") !== -1) {
            console.log("[RAT-CONTACTS] applyBatch on contacts: " +
                operations.size() + " operations");
            if (operations.size() > 3) {
                console.log("  [ALERT] Bulk contact manipulation — injection pattern");
            }
            if (operations.size() > 10) {
                console.log("  [CRITICAL] Mass contact replacement — Crocodilus pattern");
            }
        }
        return this.applyBatch(authority, operations);
    };

    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues')
        .implementation = function(uri, values) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("contacts") !== -1 || uriStr.indexOf("phone") !== -1) {
            console.log("[RAT-CONTACTS] insert: " + uriStr);
            if (values !== null) {
                var name = values.getAsString("display_name");
                var number = values.getAsString("data1");
                if (name) console.log("  Name: " + name);
                if (number) console.log("  Number: " + number);
            }
        }
        return this.insert(uri, values);
    };
});

// ================================================================
//  RAT HOOK 9: Remote Shell Monitor
//  Families: SpyNote, Brokewell
// ================================================================
Java.perform(function() {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        console.log("[RAT-SHELL] Runtime.exec: " + cmd);
        var dangerous = ["su", "pm ", "am ", "settings ", "dumpsys", "getprop",
            "cat /", "ls /", "mount", "chmod", "chown", "rm ", "cp ", "mv "];
        var isDangerous = dangerous.some(function(d) { return cmd.indexOf(d) !== -1; });
        if (isDangerous) {
            console.log("  [ALERT] Dangerous command execution");
        }
        if (cmd.indexOf("su") === 0 || cmd.indexOf("/system/bin/su") !== -1) {
            console.log("  [CRITICAL] Root shell — full device compromise");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        var cmd = cmdArray.join(" ");
        console.log("[RAT-SHELL] Runtime.exec(array): " + cmd);
        return this.exec(cmdArray);
    };

    // ProcessBuilder alternative
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function() {
        var cmdList = this.command();
        var cmdStr = "";
        for (var i = 0; i < cmdList.size(); i++) {
            cmdStr += cmdList.get(i) + " ";
        }
        console.log("[RAT-SHELL] ProcessBuilder.start: " + cmdStr.trim());
        return this.start();
    };
});

// ================================================================
//  RAT HOOK 10: Security App Removal Monitor
//  Families: TrickMo, SOVA, Cerberus, BRATA
// ================================================================
Java.perform(function() {
    var avPackages = [
        "com.avast", "com.kaspersky", "com.bitdefender", "org.malwarebytes",
        "com.symantec", "com.eset", "com.mcafee", "com.avg", "com.lookout",
        "com.trendmicro", "com.sophos"
    ];

    // Monitor package queries (AV discovery phase)
    var PackageManager = Java.use("android.content.pm.PackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int')
        .implementation = function(packageName, flags) {
        var isAv = avPackages.some(function(av) { return packageName.indexOf(av) !== -1; });
        if (isAv) {
            console.log("[RAT-AVKILL] AV package query: " + packageName);
        }
        return this.getPackageInfo(packageName, flags);
    };

    // Monitor uninstall intents
    try {
        var Intent = Java.use("android.content.Intent");
        var origSetData = Intent.setData.implementation;
        Intent.setData.implementation = function(data) {
            if (data !== null) {
                var dataStr = data.toString();
                if (dataStr.indexOf("package:") !== -1) {
                    var pkg = dataStr.replace("package:", "");
                    var isAv = avPackages.some(function(av) { return pkg.indexOf(av) !== -1; });
                    if (isAv) {
                        console.log("[RAT-AVKILL] Uninstall intent for AV: " + pkg);
                        console.log("  [CRITICAL] Security app removal — defense evasion");
                    }
                }
            }
            return this.setData(data);
        };
    } catch(e) {}

    // Play Protect disable via settings
    try {
        var Settings = Java.use("android.provider.Settings$Secure");
        Settings.putInt.overload('android.content.ContentResolver', 'java.lang.String', 'int')
            .implementation = function(resolver, name, value) {
            if (name.indexOf("package_verifier") !== -1 || name.indexOf("play_protect") !== -1) {
                console.log("[RAT-AVKILL] Settings write: " + name + " = " + value);
                if (value === 0) {
                    console.log("  [CRITICAL] Play Protect / verifier disabled");
                }
            }
            return this.putInt(resolver, name, value);
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 11: Factory Reset / Anti-Forensics Monitor
//  Family: BRATA
// ================================================================
Java.perform(function() {
    try {
        var DevicePolicyManager = Java.use("android.app.admin.DevicePolicyManager");
        DevicePolicyManager.wipeData.overload('int').implementation = function(flags) {
            console.log("[RAT-WIPE] DevicePolicyManager.wipeData(flags=" + flags + ")");
            console.log("  [CRITICAL] Remote factory reset — BRATA anti-forensics");
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
            // Block the wipe for analysis
            console.log("  [BLOCKED] Wipe blocked by Frida hook for analysis");
            // return this.wipeData(flags);  // Uncomment to allow
        };
    } catch(e) {}

    // Recovery command injection
    var Runtime = Java.use("java.lang.Runtime");
    // Covered by RAT HOOK 9, but add specific wipe detection
    try {
        var RecoverySystem = Java.use("android.os.RecoverySystem");
        RecoverySystem.rebootWipeUserData.implementation = function(context) {
            console.log("[RAT-WIPE] RecoverySystem.rebootWipeUserData()");
            console.log("  [CRITICAL] Factory reset via RecoverySystem");
            // Block
            console.log("  [BLOCKED] Wipe blocked by Frida hook");
        };
    } catch(e) {}
});

// ================================================================
//  RAT HOOK 12: Geolocation Tracking Monitor
//  Families: Brokewell, ToxicPanda
// ================================================================
Java.perform(function() {
    var LocationManager = Java.use("android.location.LocationManager");

    LocationManager.requestLocationUpdates.overload(
        'java.lang.String', 'long', 'float', 'android.location.LocationListener'
    ).implementation = function(provider, minTime, minDistance, listener) {
        console.log("[RAT-GEO] requestLocationUpdates:");
        console.log("  Provider: " + provider);
        console.log("  Interval: " + minTime + "ms");
        console.log("  Distance: " + minDistance + "m");
        if (minTime < 60000) {
            console.log("  [ALERT] High-frequency tracking (<1min interval)");
        }
        return this.requestLocationUpdates(provider, minTime, minDistance, listener);
    };

    LocationManager.getLastKnownLocation.implementation = function(provider) {
        var loc = this.getLastKnownLocation(provider);
        if (loc !== null) {
            console.log("[RAT-GEO] getLastKnownLocation(" + provider + "): " +
                loc.getLatitude() + ", " + loc.getLongitude());
        }
        return loc;
    };

    // Google Fused Location Provider
    try {
        var FusedClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
        FusedClient.requestLocationUpdates.implementation = function(request, callback, looper) {
            console.log("[RAT-GEO] FusedLocationProviderClient.requestLocationUpdates");
            return this.requestLocationUpdates(request, callback, looper);
        };
    } catch(e) {}
});

// ================================================================
console.log("[TAKOPII-RAT] RAT monitor loaded — 12 hook categories active");
console.log("[TAKOPII-RAT] Coverage: Camera, Audio, Screen, TOTP, Touch,");
console.log("[TAKOPII-RAT]   USSD, Notifications, Contacts, Shell, AV-Kill,");
console.log("[TAKOPII-RAT]   Factory-Reset, Geolocation");
// ================================================================
