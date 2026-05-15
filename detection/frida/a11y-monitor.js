/**
 * Takopii — AccessibilityService Dispatch Monitor
 *
 * Catches BankerA11yService.onAccessibilityEvent() full dispatch chain.
 * Detects overlay trigger (TYPE_WINDOW_STATE_CHANGED), keylogging
 * (TYPE_VIEW_TEXT_CHANGED), OTP extraction from notifications,
 * gate evaluation, and ScreenReader tree traversal.
 *
 * Hook 8:   AccessibilityService event dispatch
 * Hook 30:  AccessibilityEngine gate monitor
 * Hook 35b: ScreenReader A11y tree traversal
 *
 * Usage: frida -U -l a11y-monitor.js -f com.target.package
 */

// Hook 8: BankerA11yService Event Dispatch Monitor
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

    AccessibilityService.onAccessibilityEvent.implementation = function(event) {
        var eventType = event.getEventType();
        var pkg = event.getPackageName();
        var pkgStr = pkg ? pkg.toString() : "null";
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();

        // TYPE_WINDOW_STATE_CHANGED = 32 — overlay trigger chain
        if (eventType === 32) {
            console.log("[A11Y-OVERLAY] Window state changed:");
            console.log("  Foreground package: " + pkgStr);
            console.log("  Service package: " + callerPkg);
            console.log("  Class: " + (event.getClassName() ? event.getClassName().toString() : ""));
        }

        // TYPE_VIEW_TEXT_CHANGED = 16 — keylogging
        if (eventType === 16) {
            var text = event.getText();
            var isPassword = event.isPassword();
            console.log("[A11Y-KEYLOG] Text captured" +
                (isPassword ? " [PASSWORD]" : "") + ":");
            console.log("  Package: " + pkgStr);
            console.log("  Text length: " + (text ? text.size() : 0));
            if (isPassword) {
                console.log("  [CRITICAL] Password field keystroke captured by " + callerPkg);
            }
        }

        // TYPE_NOTIFICATION_STATE_CHANGED = 64 — notification OTP capture
        if (eventType === 64) {
            console.log("[A11Y-NOTIF] Notification event:");
            console.log("  Source package: " + pkgStr);
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
});

// Hook 30: AccessibilityEngine Gate Monitor
Java.perform(function() {
    try {
        var AppConfig = Java.use("com.skyweather.forecast.core.AppConfig");

        // Monitor endpoint safety check (RFC1918 gate)
        AppConfig.isEndpointSafe.implementation = function() {
            var result = this.isEndpointSafe();
            console.log("[GATE] AppConfig.isEndpointSafe() = " + result);
            if (!result) {
                console.log("  [GATE-FAIL] Endpoint is not RFC1918 — stealer disabled");
            }
            return result;
        };
    } catch(e) {}

    // Monitor AccessibilityService onServiceConnected (arming)
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    AccessibilityService.onServiceConnected.implementation = function() {
        console.log("[A11Y-GATE] AccessibilityService.onServiceConnected()");
        console.log("  Service armed — will now receive all UI events");
        return this.onServiceConnected();
    };
});

// Hook 35b: ScreenReader A11y Tree Traversal Monitor
Java.perform(function() {
    // Monitor getRootInActiveWindow (the entry point)
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    AccessibilityService.getRootInActiveWindow.overload()
        .implementation = function() {
        var root = this.getRootInActiveWindow();
        if (root !== null) {
            var pkg = root.getPackageName();
            console.log("[SCREEN-READ] getRootInActiveWindow() -> pkg=" + pkg);
            console.log("  [ATS-EYES] Tree root obtained — full screen scrape imminent");
            console.log("  childCount=" + root.getChildCount());
        }
        return root;
    };

    // Monitor AccessibilityNodeInfo.getChild (recursive traversal)
    var childCallCount = 0;
    var lastTreePkg = "";
    var lastTreeTime = 0;
    var NodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

    NodeInfo.getChild.overload('int').implementation = function(index) {
        var child = this.getChild(index);
        childCallCount++;

        // Log on first call of each traversal burst (>200ms gap = new traversal)
        var now = Date.now();
        if (now - lastTreeTime > 200) {
            if (childCallCount > 1) {
                console.log("[SCREEN-READ] Previous traversal: " + childCallCount +
                    " getChild() calls on pkg=" + lastTreePkg);
                if (childCallCount > 50) {
                    console.log("  [ALERT] Deep tree traversal (>" + childCallCount +
                        " nodes) — ATS full-screen reading pattern");
                }
            }
            childCallCount = 1;
            var pkg = this.getPackageName();
            lastTreePkg = pkg ? pkg.toString() : "unknown";
        }
        lastTreeTime = now;

        return child;
    };

    // Monitor findAccessibilityNodeInfosByViewId (targeted element lookup)
    NodeInfo.findAccessibilityNodeInfosByViewId.implementation = function(viewId) {
        var result = this.findAccessibilityNodeInfosByViewId(viewId);
        console.log("[SCREEN-READ] findByViewId: '" + viewId + "' -> " +
            (result ? result.size() : 0) + " matches");
        // ATS pattern: searching for known banking app view IDs
        if (viewId && (viewId.indexOf("amount") !== -1 || viewId.indexOf("iban") !== -1 ||
            viewId.indexOf("confirm") !== -1 || viewId.indexOf("transfer") !== -1 ||
            viewId.indexOf("otp") !== -1 || viewId.indexOf("pin") !== -1 ||
            viewId.indexOf("password") !== -1 || viewId.indexOf("balance") !== -1)) {
            console.log("  [ATS-TARGET] Banking-relevant view ID searched");
        }
        return result;
    };

    // Monitor findAccessibilityNodeInfosByText (text-based screen detection)
    NodeInfo.findAccessibilityNodeInfosByText.implementation = function(text) {
        var result = this.findAccessibilityNodeInfosByText(text);
        console.log("[SCREEN-READ] findByText: '" + text + "' -> " +
            (result ? result.size() : 0) + " matches");
        // ATS screen-state detection: checking for navigation keywords
        var lower = text.toLowerCase();
        if (lower.indexOf("transfer") !== -1 || lower.indexOf("confirm") !== -1 ||
            lower.indexOf("code") !== -1 || lower.indexOf("successful") !== -1 ||
            lower.indexOf("verify") !== -1 || lower.indexOf("balance") !== -1) {
            console.log("  [ATS-STATE] Screen-state detection keyword searched");
        }
        return result;
    };

    // Monitor performAction — the ATS execution phase
    NodeInfo.performAction.overload('int').implementation = function(action) {
        var actionName = "unknown";
        switch(action) {
            case 16: actionName = "ACTION_CLICK"; break;
            case 32: actionName = "ACTION_LONG_CLICK"; break;
            case 64: actionName = "ACTION_FOCUS"; break;
            case 4096: actionName = "ACTION_SCROLL_FORWARD"; break;
            case 8192: actionName = "ACTION_SCROLL_BACKWARD"; break;
        }
        var viewId = this.getViewIdResourceName();
        var text = this.getText();
        console.log("[SCREEN-READ] performAction: " + actionName +
            " on viewId=" + (viewId || "none") +
            " text='" + (text ? text.toString().substring(0, 30) : "") + "'");

        if (action === 16) { // ACTION_CLICK
            console.log("  [ATS-INJECT] Synthetic click injected via performAction");
        }
        return this.performAction(action);
    };

    // Monitor ACTION_SET_TEXT (credential auto-fill)
    NodeInfo.performAction.overload('int', 'android.os.Bundle').implementation = function(action, args) {
        if (action === 0x200000) { // ACTION_SET_TEXT = 2097152 = 0x200000
            var setText = args ? args.getCharSequence("ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE") : null;
            var viewId = this.getViewIdResourceName();
            console.log("[SCREEN-READ] ACTION_SET_TEXT:");
            console.log("  viewId=" + (viewId || "none"));
            console.log("  text_len=" + (setText ? setText.length() : 0));
            // Don't log actual text (could be OTP or credential)
            // But DO flag the field type
            if (viewId) {
                var vid = viewId.toLowerCase();
                if (vid.indexOf("amount") !== -1) {
                    console.log("  [ATS-FILL] Amount field filled — transfer in progress");
                } else if (vid.indexOf("iban") !== -1 || vid.indexOf("account") !== -1 ||
                           vid.indexOf("recipient") !== -1) {
                    console.log("  [ATS-FILL] Recipient field filled — mule account injection");
                } else if (vid.indexOf("otp") !== -1 || vid.indexOf("code") !== -1 ||
                           vid.indexOf("pin") !== -1) {
                    console.log("  [ATS-FILL] OTP/PIN field filled — intercepted code auto-filled");
                }
            }
        }
        return this.performAction(action, args);
    };
});
