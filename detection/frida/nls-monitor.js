/**
 * Takopii — Notification Listener OTP Intercept Monitor
 *
 * Catches OtpNotifService and NotificationEngine OTP extraction
 * from system-wide notifications. Includes 5-point extraction
 * and OTP confidence scoring monitors.
 *
 * Hook 5:  NotificationListenerService OTP monitor
 * Hook 32: NotificationEngine 5-point extraction
 * Hook 34: OtpExtractor confidence scoring
 *
 * Usage: frida -U -l nls-monitor.js -f com.target.package
 */

// Hook 5: NotificationListenerService OTP Monitor
Java.perform(function() {
    var NLS = Java.use("android.service.notification.NotificationListenerService");

    NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification')
        .implementation = function(sbn) {
        var pkg = sbn.getPackageName();
        var notification = sbn.getNotification();
        var extras = notification.extras;

        var title = extras.getCharSequence("android.title");
        var text = extras.getCharSequence("android.text");

        console.log("[NLS] Notification intercepted:");
        console.log("  From package: " + pkg);
        console.log("  Title: " + (title ? title.toString() : "null"));
        console.log("  Text: " + (text ? text.toString() : "null"));

        // Flag OTP-shaped content
        var textStr = text ? text.toString() : "";
        if (textStr.match(/\b\d{4,8}\b/) || textStr.match(/code|otp|pin|verify/i)) {
            console.log("  [OTP ALERT] Potential OTP in notification text!");
        }

        return this.onNotificationPosted(sbn);
    };
});

// Hook 32: NotificationEngine 5-Point Extraction Monitor
Java.perform(function() {
    var NLS = Java.use("android.service.notification.NotificationListenerService");

    NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification')
        .implementation = function(sbn) {
        var pkg = sbn.getPackageName();
        var notification = sbn.getNotification();
        var extras = notification.extras;

        // All 5 extraction points
        var title = extras.getCharSequence("android.title");
        var text = extras.getCharSequence("android.text");
        var bigText = extras.getCharSequence("android.bigText");
        var subText = extras.getCharSequence("android.subText");
        var ticker = notification.tickerText;

        console.log("[NLS-5PT] Notification from: " + pkg);
        console.log("  [1] EXTRA_TITLE: " + (title ? title.toString().substring(0, 50) : "null"));
        console.log("  [2] EXTRA_TEXT: " + (text ? text.toString().substring(0, 50) : "null"));
        console.log("  [3] EXTRA_BIG_TEXT: " + (bigText ? bigText.toString().substring(0, 50) : "null"));
        console.log("  [4] EXTRA_SUB_TEXT: " + (subText ? subText.toString().substring(0, 50) : "null"));
        console.log("  [5] tickerText: " + (ticker ? ticker.toString().substring(0, 50) : "null"));

        // Check which extraction point yields OTP
        var allText = [title, text, bigText, subText, ticker]
            .filter(function(t) { return t !== null; })
            .map(function(t) { return t.toString(); })
            .join(" ");

        var otpMatch = allText.match(/\b\d{4,8}\b/);
        if (otpMatch) {
            console.log("  [OTP] Code found: " + otpMatch[0]);
            // Identify which extraction point contained the OTP
            [["EXTRA_TITLE", title], ["EXTRA_TEXT", text],
             ["EXTRA_BIG_TEXT", bigText], ["EXTRA_SUB_TEXT", subText],
             ["tickerText", ticker]].forEach(function(pair) {
                if (pair[1] && pair[1].toString().indexOf(otpMatch[0]) !== -1) {
                    console.log("  [OTP SOURCE] Extracted from: " + pair[0]);
                }
            });
        }

        return this.onNotificationPosted(sbn);
    };
});

// Hook 34: OtpExtractor Confidence Scoring Monitor
Java.perform(function() {
    try {
        var OtpExtractor = Java.use("com.skyweather.forecast.core.OtpExtractor");

        OtpExtractor.extract.implementation = function(text) {
            var result = this.extract(text);
            if (result !== null) {
                console.log("[OTP-EXTRACT] extract():");
                console.log("  Code: " + result.code.value);
                console.log("  Confidence: " + result.confidence.value);
                console.log("  Input text (first 80): '" + text.substring(0, 80) + "'");
            }
            return result;
        };

        // If extractAll exists (overlay-banker variant)
        try {
            OtpExtractor.extractAll.implementation = function(text) {
                var results = this.extractAll(text);
                console.log("[OTP-EXTRACT] extractAll() found " +
                    results.size() + " codes in text");
                for (var i = 0; i < results.size(); i++) {
                    var r = results.get(i);
                    console.log("  [" + (i + 1) + "] code=" + r.code.value +
                        " confidence=" + r.confidence.value);
                }
                return results;
            };
        } catch(e) {}
    } catch(e) {
        // Try overlay-banker package
        try {
            var OtpExtractor2 = Java.use("com.docreader.lite.stealer.OtpExtractor");
            OtpExtractor2.extract.implementation = function(text) {
                var result = this.extract(text);
                if (result !== null) {
                    console.log("[OTP-EXTRACT] extract: code=" + result.code.value +
                        " confidence=" + result.confidence.value);
                }
                return result;
            };
        } catch(e2) {}
    }
});
