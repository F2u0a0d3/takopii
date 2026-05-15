/**
 * Takopii — ATS Gesture Injection + Auto-Fill Monitor
 *
 * Catches GestureInjector.tapAt()/swipe() and credential auto-fill
 * via AccessibilityNodeInfo.performAction. High-confidence ATS:
 * dispatchGesture from non-foreground package during banking session.
 *
 * Hook 9:  dispatchGesture + performGlobalAction + performAction ATS
 * Hook 31: CredentialStore buffer monitor
 * Hook 33: SmsInterceptor priority monitor
 *
 * Usage: frida -U -l ats-monitor.js -f com.target.package
 */

// Hook 9: dispatchGesture ATS Monitor
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

    AccessibilityService.dispatchGesture.overload(
        'android.accessibilityservice.GestureDescription',
        'android.accessibilityservice.AccessibilityService$GestureResultCallback',
        'android.os.Handler'
    ).implementation = function(gesture, callback, handler) {
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();

        console.log("[ATS-GESTURE] dispatchGesture called!");
        console.log("  Injector package: " + callerPkg);
        console.log("  Stroke count: " + gesture.getStrokeCount());

        for (var i = 0; i < gesture.getStrokeCount(); i++) {
            var stroke = gesture.getStroke(i);
            console.log("  Stroke " + i + ": duration=" + stroke.getDuration() +
                "ms, start=" + stroke.getStartTime() + "ms");
        }

        console.log("  [CRITICAL] Synthetic gesture injection from AccessibilityService");
        console.log("  Stack: " + Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));

        return this.dispatchGesture(gesture, callback, handler);
    };

    // Also hook performGlobalAction for PATH 3 detection
    AccessibilityService.performGlobalAction.implementation = function(action) {
        var actions = {1: "BACK", 2: "HOME", 4: "NOTIFICATIONS", 8: "RECENTS"};
        console.log("[ATS-GLOBAL] performGlobalAction: " +
            (actions[action] || "UNKNOWN(" + action + ")"));
        return this.performGlobalAction(action);
    };

    // Hook AccessibilityNodeInfo.performAction for PATH 1 detection
    var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    ANI.performAction.overload('int', 'android.os.Bundle').implementation = function(action, args) {
        // ACTION_SET_TEXT = 2097152 — credential field injection
        if (action === 2097152 && args) {
            var text = args.getCharSequence("ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE");
            console.log("[ATS-INJECT] ACTION_SET_TEXT on node:");
            console.log("  Text length: " + (text ? text.length() : 0));
            console.log("  View ID: " + (this.getViewIdResourceName() || "none"));
        }
        return this.performAction(action, args);
    };
});

// Hook 31: CredentialStore Buffer Monitor
Java.perform(function() {
    try {
        var CredentialStore = Java.use("com.skyweather.forecast.core.CredentialStore");

        CredentialStore.capture.implementation = function(event) {
            console.log("[CREDSTORE] capture: pkg=" + event.packageName.value +
                " type=" + event.eventType.value +
                " text_len=" + event.text.value.length);
            console.log("  Buffer size: " + this.size());
            return this.capture(event);
        };

        CredentialStore.drain.implementation = function() {
            var result = this.drain();
            console.log("[CREDSTORE] drain() — " + result.size() + " events flushed for exfil");
            if (result.size() > 0) {
                console.log("  [ALERT] Credential buffer drained — exfil in progress");
            }
            return result;
        };

        CredentialStore.peekAll.implementation = function() {
            var result = this.peekAll();
            console.log("[CREDSTORE] peekAll() — " + result.size() +
                " events (non-destructive read)");
            console.log("  [ATS] OTP lookup — scanning buffer for latest OTP entry");
            return result;
        };
    } catch(e) {
        console.log("[CREDSTORE] Not in this specimen: " + e);
    }
});

// Hook 33: SmsInterceptor Priority Monitor
Java.perform(function() {
    var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");

    BroadcastReceiver.onReceive.implementation = function(context, intent) {
        var action = intent.getAction();
        if (action && action.indexOf("SMS_RECEIVED") !== -1) {
            console.log("[SMS-INTERCEPT] onReceive: " + action);
            console.log("  Receiver: " + this.getClass().getName());
            console.log("  Is ordered: " + this.isOrderedBroadcast());

            // Check for abortBroadcast (suppresses notification)
            var origAbort = this.getAbortBroadcast.bind(this);
        }
        var result = this.onReceive(context, intent);

        // Check if broadcast was aborted (SMS suppression)
        if (action && action.indexOf("SMS_RECEIVED") !== -1) {
            if (this.getAbortBroadcast()) {
                console.log("  [CRITICAL] abortBroadcast() called — SMS notification suppressed!");
            }
        }
        return result;
    };

    // Also monitor multi-part SMS concatenation
    var SmsMessage = Java.use("android.telephony.SmsMessage");
    SmsMessage.createFromPdu.overload('[B', 'java.lang.String').implementation = function(pdu, format) {
        var msg = this.createFromPdu(pdu, format);
        if (msg !== null) {
            console.log("[SMS-INTERCEPT] SmsMessage parsed:");
            console.log("  From: " + msg.getOriginatingAddress());
            console.log("  Body length: " + (msg.getMessageBody() ?
                msg.getMessageBody().length() : 0));
        }
        return msg;
    };
});
