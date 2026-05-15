/**
 * SkyWeather Forecast — Defender Frida Monitor
 *
 * Real-time instrumentation of all specimen offensive primitives.
 * Hooks every sensitive API call, logs structured events, alerts
 * on high-confidence banker behavior patterns.
 *
 * Usage:
 *   frida -U -f com.skyweather.forecast -l skyweather-monitor.js --no-pause
 *   frida -U com.skyweather.forecast -l skyweather-monitor.js
 *
 * Output: structured log lines to console. Pipe to file for analysis:
 *   frida -U ... -l skyweather-monitor.js 2>&1 | tee monitor.log
 *
 * Modules:
 *   [A11Y]     AccessibilityService event capture + gesture injection
 *   [OVERLAY]  TYPE_ACCESSIBILITY_OVERLAY window creation
 *   [NLS]      NotificationListenerService OTP extraction
 *   [SMS]      BroadcastReceiver SMS interception
 *   [CRED]     CredentialStore buffer operations
 *   [EXFIL]    SyncTask network transmission
 *   [DCL]      DexClassLoader payload loading
 *   [DGA]      DomainResolver MD5-seeded generation
 *   [C2]       UpdateChannel config fetch
 *   [ATS]      AtsEngine command execution
 *   [REFL]     Reflection API hiding (RuntimeBridge)
 */

'use strict';

// ── Severity levels ──────────────────────────────────────────────

const SEV = {
    CRITICAL: '\x1b[91m[CRITICAL]\x1b[0m',
    HIGH:     '\x1b[93m[HIGH]\x1b[0m',
    MEDIUM:   '\x1b[33m[MEDIUM]\x1b[0m',
    LOW:      '\x1b[36m[LOW]\x1b[0m',
    INFO:     '\x1b[32m[INFO]\x1b[0m',
};

function ts() {
    return new Date().toISOString().substr(11, 12);
}

function log(module, severity, msg) {
    console.log(`[${ts()}] [${module}] ${severity} ${msg}`);
}

// Event counter for pattern detection
const eventCounts = {};
function countEvent(module) {
    eventCounts[module] = (eventCounts[module] || 0) + 1;
    return eventCounts[module];
}

// ── Wait for Java runtime ────────────────────────────────────────

Java.perform(function() {

    log('INIT', SEV.INFO, 'SkyWeather monitor attached to ' + Java.use('android.app.ActivityThread').currentPackageName());

    // ─────────────────────────────────────────────────────────────
    // MODULE: AccessibilityService — credential capture + gestures
    // ─────────────────────────────────────────────────────────────

    try {
        var AccessibilityEngine = Java.use('com.skyweather.forecast.core.AccessibilityEngine');

        AccessibilityEngine.onAccessibilityEvent.implementation = function(event) {
            if (event !== null) {
                var eventType = event.getEventType();
                var pkg = event.getPackageName();
                var text = event.getText();

                var typeStr = {
                    1: 'VIEW_CLICKED', 2: 'VIEW_LONG_CLICKED',
                    4: 'VIEW_SELECTED', 8: 'VIEW_FOCUSED',
                    16: 'VIEW_TEXT_CHANGED', 32: 'WINDOW_STATE_CHANGED',
                    64: 'NOTIFICATION_STATE_CHANGED',
                    2048: 'VIEW_TEXT_SELECTION_CHANGED',
                    4096: 'VIEW_SCROLLED',
                }[eventType] || 'TYPE_' + eventType;

                var n = countEvent('A11Y');

                if (eventType === 16) { // TEXT_CHANGED — keystroke capture
                    log('A11Y', SEV.HIGH,
                        'TEXT_CHANGED pkg=' + pkg +
                        ' text="' + (text ? text.toString().substring(0, 50) : '') + '"' +
                        ' [event #' + n + ']');
                } else if (eventType === 32) { // WINDOW_STATE_CHANGED
                    log('A11Y', SEV.MEDIUM,
                        'WINDOW_CHANGED pkg=' + pkg +
                        ' class=' + event.getClassName() +
                        ' [event #' + n + ']');
                } else if (eventType === 64) { // NOTIFICATION
                    log('A11Y', SEV.HIGH,
                        'NOTIFICATION pkg=' + pkg +
                        ' text="' + (text ? text.toString().substring(0, 80) : '') + '"');
                }

                // Alert on high event volume (banker pattern)
                if (n === 50) {
                    log('A11Y', SEV.CRITICAL,
                        'HIGH EVENT VOLUME: 50+ A11y events captured — banker behavior pattern');
                }
            }
            this.onAccessibilityEvent(event);
        };

        AccessibilityEngine.onServiceConnected.implementation = function() {
            log('A11Y', SEV.CRITICAL, 'SERVICE CONNECTED — AccessibilityEngine armed');
            this.onServiceConnected();
        };

        log('A11Y', SEV.INFO, 'AccessibilityEngine hooks installed');
    } catch(e) {
        log('A11Y', SEV.LOW, 'Class not loaded yet (deferred): ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: Overlay — TYPE_ACCESSIBILITY_OVERLAY injection
    // ─────────────────────────────────────────────────────────────

    try {
        var WindowManager = Java.use('android.view.WindowManager');
        var WindowManagerLayoutParams = Java.use('android.view.WindowManager$LayoutParams');

        // Hook WindowManager.addView to catch overlay creation
        var wmImpl = Java.use('android.view.WindowManagerImpl');
        wmImpl.addView.implementation = function(view, params) {
            if (params !== null) {
                var lp = Java.cast(params, WindowManagerLayoutParams);
                var windowType = lp.type.value;

                // TYPE_ACCESSIBILITY_OVERLAY = 2032
                if (windowType === 2032) {
                    log('OVERLAY', SEV.CRITICAL,
                        'TYPE_ACCESSIBILITY_OVERLAY (2032) window added — credential capture overlay!');
                    log('OVERLAY', SEV.HIGH,
                        'Window flags=0x' + lp.flags.value.toString(16) +
                        ' gravity=' + lp.gravity.value +
                        ' format=' + lp.format.value);
                }
                // TYPE_APPLICATION_OVERLAY = 2038
                else if (windowType === 2038) {
                    log('OVERLAY', SEV.HIGH,
                        'TYPE_APPLICATION_OVERLAY (2038) window added');
                }
            }
            this.addView(view, params);
        };

        log('OVERLAY', SEV.INFO, 'WindowManager.addView hook installed');
    } catch(e) {
        log('OVERLAY', SEV.LOW, 'WindowManager hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: NotificationListenerService — OTP intercept
    // ─────────────────────────────────────────────────────────────

    try {
        var NotificationEngine = Java.use('com.skyweather.forecast.core.NotificationEngine');

        NotificationEngine.onNotificationPosted.implementation = function(sbn) {
            if (sbn !== null) {
                var pkg = sbn.getPackageName();
                var notification = sbn.getNotification();
                var extras = notification.extras.value;
                var title = extras.getCharSequence('android.title');
                var text = extras.getCharSequence('android.text');

                log('NLS', SEV.HIGH,
                    'NOTIFICATION_CAPTURED pkg=' + pkg +
                    ' title="' + (title || '') + '"' +
                    ' text="' + (text ? text.toString().substring(0, 60) : '') + '"');

                countEvent('NLS');
            }
            this.onNotificationPosted(sbn);
        };

        NotificationEngine.onListenerConnected.implementation = function() {
            log('NLS', SEV.CRITICAL, 'NotificationListenerService CONNECTED — all notifications visible');
            this.onListenerConnected();
        };

        log('NLS', SEV.INFO, 'NotificationEngine hooks installed');
    } catch(e) {
        log('NLS', SEV.LOW, 'NotificationEngine not loaded yet: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: SMS interception
    // ─────────────────────────────────────────────────────────────

    try {
        var SmsInterceptor = Java.use('com.skyweather.forecast.core.SmsInterceptor');

        SmsInterceptor.onReceive.implementation = function(context, intent) {
            var action = intent ? intent.getAction() : 'null';
            log('SMS', SEV.CRITICAL,
                'SMS_RECEIVED intercepted — action=' + action);
            countEvent('SMS');
            this.onReceive(context, intent);
        };

        log('SMS', SEV.INFO, 'SmsInterceptor hook installed');
    } catch(e) {
        log('SMS', SEV.LOW, 'SmsInterceptor not loaded yet: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: OTP extraction
    // ─────────────────────────────────────────────────────────────

    try {
        var OtpExtractor = Java.use('com.skyweather.forecast.core.OtpExtractor');

        OtpExtractor.extract.implementation = function(text) {
            var result = this.extract(text);
            if (result !== null) {
                log('OTP', SEV.CRITICAL,
                    'OTP EXTRACTED: "' + result.getCode() + '"' +
                    ' confidence=' + result.getConfidence() +
                    ' from text="' + text.toString().substring(0, 60) + '"');
            }
            return result;
        };

        OtpExtractor.extractAll.implementation = function(text) {
            var results = this.extractAll(text);
            if (results.size() > 0) {
                log('OTP', SEV.CRITICAL,
                    'OTP BATCH: ' + results.size() + ' codes extracted' +
                    ' from text="' + text.toString().substring(0, 60) + '"');
            }
            return results;
        };

        log('OTP', SEV.INFO, 'OtpExtractor hooks installed');
    } catch(e) {
        log('OTP', SEV.LOW, 'OtpExtractor not loaded yet: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: CredentialStore — buffer operations
    // ─────────────────────────────────────────────────────────────

    try {
        var CredentialStore = Java.use('com.skyweather.forecast.core.CredentialStore');

        CredentialStore.capture.implementation = function(event) {
            log('CRED', SEV.HIGH,
                'BUFFERED pkg=' + event.getPackageName() +
                ' type=' + event.getEventType() +
                ' viewId=' + event.getViewId() +
                ' text="' + event.getText().substring(0, Math.min(event.getText().length, 30)) + '"');
            countEvent('CRED');
            this.capture(event);
        };

        CredentialStore.drain.implementation = function() {
            var events = this.drain();
            if (events.size() > 0) {
                log('CRED', SEV.CRITICAL,
                    'DRAIN for exfil: ' + events.size() + ' credential events');
            }
            return events;
        };

        CredentialStore.toJsonPayload.implementation = function() {
            var payload = this.toJsonPayload();
            if (payload.length > 0) {
                log('EXFIL', SEV.CRITICAL,
                    'CREDENTIAL PAYLOAD built: ' + payload.length + ' bytes');
            }
            return payload;
        };

        log('CRED', SEV.INFO, 'CredentialStore hooks installed');
    } catch(e) {
        log('CRED', SEV.LOW, 'CredentialStore not loaded yet: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: SyncTask — network exfiltration
    // ─────────────────────────────────────────────────────────────

    try {
        var SyncTask = Java.use('com.skyweather.forecast.core.SyncTask');

        SyncTask.doWork.implementation = function() {
            log('EXFIL', SEV.CRITICAL, 'SyncTask.doWork() EXECUTING — C2 beacon + exfil cycle');
            var result = this.doWork();
            log('EXFIL', SEV.HIGH, 'SyncTask result: ' + result);
            return result;
        };

        log('EXFIL', SEV.INFO, 'SyncTask hooks installed');
    } catch(e) {
        log('EXFIL', SEV.LOW, 'SyncTask not loaded yet: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: DexClassLoader — payload loading
    // ─────────────────────────────────────────────────────────────

    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');

        DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libraryPath, parent) {
            log('DCL', SEV.CRITICAL,
                'DexClassLoader CREATED' +
                ' path=' + dexPath +
                ' optDir=' + optimizedDir);
            this.$init(dexPath, optimizedDir, libraryPath, parent);
        };

        DexClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
            log('DCL', SEV.HIGH, 'DCL.loadClass("' + name + '")');
            return this.loadClass(name);
        };

        log('DCL', SEV.INFO, 'DexClassLoader hooks installed');
    } catch(e) {
        log('DCL', SEV.LOW, 'DexClassLoader hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: DGA — domain generation
    // ─────────────────────────────────────────────────────────────

    try {
        var MessageDigest = Java.use('java.security.MessageDigest');

        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            if (algorithm === 'MD5') {
                log('DGA', SEV.MEDIUM, 'MessageDigest.getInstance("MD5") — potential DGA seed hash');
                countEvent('DGA');
            }
            return this.getInstance(algorithm);
        };

        MessageDigest.digest.overload('[B').implementation = function(input) {
            var inputStr = '';
            try {
                inputStr = Java.use('java.lang.String').$new(input, 'UTF-8');
            } catch(e) {
                inputStr = '<binary ' + input.length + ' bytes>';
            }

            var result = this.digest(input);

            var algo = this.getAlgorithm();
            if (algo === 'MD5') {
                log('DGA', SEV.HIGH,
                    'MD5.digest("' + inputStr + '") — DGA seed computation');
            }
            return result;
        };

        log('DGA', SEV.INFO, 'MessageDigest hooks installed');
    } catch(e) {
        log('DGA', SEV.LOW, 'MessageDigest hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: Reflection — API hiding
    // ─────────────────────────────────────────────────────────────

    try {
        var ClassForName = Java.use('java.lang.Class');

        ClassForName.forName.overload('java.lang.String').implementation = function(name) {
            // Filter to interesting reflective lookups (skip framework noise)
            if (name.startsWith('android.os.Build') ||
                name.startsWith('android.hardware') ||
                name.startsWith('android.telephony') ||
                name.startsWith('android.app.admin') ||
                name.contains('payload') ||
                name.contains('Module')) {
                log('REFL', SEV.MEDIUM,
                    'Class.forName("' + name + '") — reflective API lookup');
                countEvent('REFL');
            }
            return this.forName(name);
        };

        log('REFL', SEV.INFO, 'Reflection hooks installed');
    } catch(e) {
        log('REFL', SEV.LOW, 'Reflection hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: Network — HttpURLConnection to C2
    // ─────────────────────────────────────────────────────────────

    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');

        HttpURLConnection.getOutputStream.implementation = function() {
            var url = this.getURL().toString();
            log('NET', SEV.HIGH,
                'HTTP OUTPUT to ' + url + ' method=' + this.getRequestMethod());
            countEvent('NET');
            return this.getOutputStream();
        };

        HttpURLConnection.getResponseCode.implementation = function() {
            var code = this.getResponseCode();
            var url = this.getURL().toString();
            log('NET', SEV.MEDIUM,
                'HTTP RESPONSE ' + code + ' from ' + url);
            return code;
        };

        log('NET', SEV.INFO, 'HttpURLConnection hooks installed');
    } catch(e) {
        log('NET', SEV.LOW, 'HttpURLConnection hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: ATS — Automatic Transfer System
    // ─────────────────────────────────────────────────────────────

    try {
        var AtsEngine = Java.use('com.skyweather.forecast.core.AtsEngine');

        AtsEngine.onTargetForegrounded.implementation = function(pkg) {
            log('ATS', SEV.CRITICAL,
                'TARGET FOREGROUNDED: ' + pkg + ' — ATS activation!');
            this.onTargetForegrounded(pkg);
        };

        AtsEngine.loadCommands.implementation = function(commands) {
            log('ATS', SEV.CRITICAL,
                'ATS COMMANDS LOADED: ' + commands.size() + ' commands in queue');
            for (var i = 0; i < commands.size(); i++) {
                var cmd = commands.get(i);
                log('ATS', SEV.HIGH,
                    '  cmd[' + i + ']: action=' + cmd.getAction() +
                    ' target=' + cmd.getTargetId() +
                    ' value=' + cmd.getValue());
            }
            this.loadCommands(commands);
        };

        AtsEngine.onTargetLostForeground.implementation = function() {
            log('ATS', SEV.HIGH, 'TARGET LOST FOREGROUND — ATS aborting');
            this.onTargetLostForeground();
        };

        log('ATS', SEV.INFO, 'AtsEngine hooks installed');
    } catch(e) {
        log('ATS', SEV.LOW, 'AtsEngine not loaded yet: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: GestureInjector — synthetic input
    // ─────────────────────────────────────────────────────────────

    try {
        var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');

        AccessibilityService.dispatchGesture.implementation = function(gesture, callback, handler) {
            log('GESTURE', SEV.CRITICAL,
                'dispatchGesture() — synthetic touch injection!');
            countEvent('GESTURE');
            return this.dispatchGesture(gesture, callback, handler);
        };

        AccessibilityService.performGlobalAction.implementation = function(action) {
            var actionStr = {
                1: 'BACK', 2: 'HOME', 3: 'RECENTS',
                4: 'NOTIFICATIONS', 5: 'QUICK_SETTINGS',
                6: 'POWER_DIALOG', 11: 'TOGGLE_SPLIT_SCREEN',
                12: 'LOCK_SCREEN'
            }[action] || 'ACTION_' + action;

            log('GESTURE', SEV.HIGH,
                'performGlobalAction(' + actionStr + ')');
            return this.performGlobalAction(action);
        };

        log('GESTURE', SEV.INFO, 'Gesture injection hooks installed');
    } catch(e) {
        log('GESTURE', SEV.LOW, 'Gesture hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: AccessibilityNodeInfo — SET_TEXT cross-package
    // ─────────────────────────────────────────────────────────────

    try {
        var NodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');

        NodeInfo.performAction.overload('int', 'android.os.Bundle').implementation = function(action, args) {
            // ACTION_SET_TEXT = 0x200000 = 2097152
            if (action === 0x200000 && args !== null) {
                var text = args.getCharSequence('ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE');
                log('ATS', SEV.CRITICAL,
                    'performAction(SET_TEXT) text="' + (text ? text.toString().substring(0, 30) : '') + '"' +
                    ' — ATS form fill!');
                countEvent('ATS_SET_TEXT');
            }
            return this.performAction(action, args);
        };

        log('ATS', SEV.INFO, 'AccessibilityNodeInfo.performAction hook installed');
    } catch(e) {
        log('ATS', SEV.LOW, 'NodeInfo hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // MODULE: File operations — anti-forensics
    // ─────────────────────────────────────────────────────────────

    try {
        var File = Java.use('java.io.File');

        File.delete.implementation = function() {
            var path = this.getAbsolutePath();
            // Only log app-private paths (filter system noise)
            if (path.contains('skyweather') || path.contains('cache_data') ||
                path.contains('update_cache') || path.contains('oat_cache')) {
                log('FORENSIC', SEV.HIGH,
                    'FILE DELETE: ' + path + ' — anti-forensics cleanup');
                countEvent('FORENSIC');
            }
            return this.delete();
        };

        log('FORENSIC', SEV.INFO, 'File.delete hook installed');
    } catch(e) {
        log('FORENSIC', SEV.LOW, 'File hook failed: ' + e.message);
    }

    // ─────────────────────────────────────────────────────────────
    // Summary banner
    // ─────────────────────────────────────────────────────────────

    log('INIT', SEV.INFO, '');
    log('INIT', SEV.INFO, '=== SkyWeather Monitor Active ===');
    log('INIT', SEV.INFO, 'Modules: A11Y, OVERLAY, NLS, SMS, OTP, CRED, EXFIL, DCL, DGA, REFL, NET, ATS, GESTURE, FORENSIC');
    log('INIT', SEV.INFO, 'Waiting for specimen activation (dormancy + interaction gates)...');
    log('INIT', SEV.INFO, '');

});
