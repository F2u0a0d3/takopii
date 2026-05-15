/**
 * SkyWeather Forecast — Credential Watcher (focused)
 *
 * Lightweight Frida script — watches ONLY credential flow:
 *   CredentialStore.capture() → drain() → SyncTask exfil
 *
 * Use this when you want clean credential timeline without
 * the noise of every A11y event and network call.
 *
 * Usage:
 *   frida -U com.skyweather.forecast -l credential-watcher.js
 */

'use strict';

function ts() {
    return new Date().toISOString().substr(11, 12);
}

var captureCount = 0;
var drainCount = 0;

Java.perform(function() {

    console.log('[' + ts() + '] Credential watcher attached\n');

    // ── CredentialStore.capture — every credential buffered ──────

    try {
        var CredentialStore = Java.use('com.skyweather.forecast.core.CredentialStore');

        CredentialStore.capture.implementation = function(event) {
            captureCount++;
            var pkg = event.getPackageName();
            var viewId = event.getViewId();
            var text = event.getText();
            var etype = event.getEventType();

            // Severity color by type
            var prefix = '\x1b[37m';  // white default
            if (etype === 'pwd' || etype === 'overlay_pwd') prefix = '\x1b[91m';     // red
            else if (etype.startsWith('otp')) prefix = '\x1b[93m';                     // yellow
            else if (etype === 'usr' || etype === 'overlay_usr') prefix = '\x1b[96m'; // cyan
            else if (etype.startsWith('ats')) prefix = '\x1b[95m';                     // magenta

            console.log(prefix + '[' + ts() + '] #' + captureCount +
                ' [' + etype + '] ' + pkg +
                ' | ' + viewId +
                ' | "' + text.substring(0, Math.min(text.length, 50)) + '"' +
                '\x1b[0m');

            this.capture(event);
        };

        // ── drain — exfil cycle ─────────────────────────────────

        CredentialStore.drain.implementation = function() {
            var events = this.drain();
            var count = events.size();
            if (count > 0) {
                drainCount++;
                console.log('\x1b[91m[' + ts() + '] === DRAIN #' + drainCount +
                    ': ' + count + ' events shipped to C2 ===\x1b[0m');
            }
            return events;
        };

        // ── buffer status ───────────────────────────────────────

        CredentialStore.hasPending.implementation = function() {
            var pending = this.hasPending();
            if (pending) {
                console.log('[' + ts() + '] Buffer has pending credentials (size=' +
                    this.size() + ')');
            }
            return pending;
        };

        console.log('[' + ts() + '] CredentialStore hooks active');

    } catch(e) {
        console.log('[!] CredentialStore not loaded: ' + e.message);
    }

    // ── OtpExtractor — watch OTP extraction specifically ────────

    try {
        var OtpExtractor = Java.use('com.skyweather.forecast.core.OtpExtractor');

        OtpExtractor.extract.implementation = function(text) {
            var result = this.extract(text);
            if (result !== null) {
                console.log('\x1b[93m[' + ts() + '] OTP FOUND: "' +
                    result.getCode() + '" (' + result.getConfidence() + ')' +
                    ' in: "' + text.toString().substring(0, 40) + '..."\x1b[0m');
            }
            return result;
        };

        console.log('[' + ts() + '] OtpExtractor hooks active');
    } catch(e) {
        console.log('[!] OtpExtractor not loaded: ' + e.message);
    }

    console.log('[' + ts() + '] Watching credential flow...\n');
});
