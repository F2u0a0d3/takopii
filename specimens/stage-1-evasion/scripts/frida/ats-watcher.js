/**
 * SkyWeather Forecast — ATS Watcher (focused)
 *
 * Watches Automatic Transfer System execution in real-time:
 *   Command loading → target foreground → gesture injection → result
 *
 * Usage:
 *   frida -U com.skyweather.forecast -l ats-watcher.js
 */

'use strict';

function ts() {
    return new Date().toISOString().substr(11, 12);
}

Java.perform(function() {

    console.log('[' + ts() + '] ATS watcher attached\n');

    // ── AtsEngine — command lifecycle ───────────────────────────

    try {
        var AtsEngine = Java.use('com.skyweather.forecast.core.AtsEngine');

        AtsEngine.loadCommands.implementation = function(commands) {
            console.log('\x1b[95m[' + ts() + '] ATS ARMED: ' + commands.size() + ' commands queued\x1b[0m');
            for (var i = 0; i < commands.size(); i++) {
                var cmd = commands.get(i);
                console.log('  [' + i + '] ' + cmd.getAction() +
                    (cmd.getTargetId() ? ' target=' + cmd.getTargetId() : '') +
                    (cmd.getValue() ? ' value="' + cmd.getValue() + '"' : '') +
                    (cmd.getPatterns() ? ' patterns=' + cmd.getPatterns() : ''));
            }
            this.loadCommands(commands);
        };

        AtsEngine.onTargetForegrounded.implementation = function(pkg) {
            console.log('\x1b[91m[' + ts() + '] === ATS TRIGGERED === target=' + pkg + '\x1b[0m');
            this.onTargetForegrounded(pkg);
        };

        AtsEngine.onTargetLostForeground.implementation = function() {
            console.log('\x1b[93m[' + ts() + '] ATS: target lost foreground\x1b[0m');
            this.onTargetLostForeground();
        };

        console.log('[' + ts() + '] AtsEngine hooks active');
    } catch(e) {
        console.log('[!] AtsEngine not loaded: ' + e.message);
    }

    // ── GestureInjector — synthetic input ───────────────────────

    try {
        var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');

        AccessibilityService.dispatchGesture.implementation = function(gesture, callback, handler) {
            console.log('\x1b[91m[' + ts() + '] GESTURE: dispatchGesture() — synthetic tap\x1b[0m');
            return this.dispatchGesture(gesture, callback, handler);
        };

        AccessibilityService.performGlobalAction.implementation = function(action) {
            var name = {1:'BACK', 2:'HOME', 3:'RECENTS', 4:'NOTIFICATIONS'}[action] || action;
            console.log('\x1b[93m[' + ts() + '] GLOBAL: ' + name + '\x1b[0m');
            return this.performGlobalAction(action);
        };

        console.log('[' + ts() + '] Gesture hooks active');
    } catch(e) {
        console.log('[!] Gesture hooks failed: ' + e.message);
    }

    // ── AccessibilityNodeInfo.performAction — SET_TEXT ───────────

    try {
        var NodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');

        NodeInfo.performAction.overload('int', 'android.os.Bundle').implementation = function(action, args) {
            if (action === 0x200000 && args !== null) { // SET_TEXT
                var text = args.getCharSequence('ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE');
                console.log('\x1b[91m[' + ts() + '] SET_TEXT: "' +
                    (text ? text.toString().substring(0, 40) : '') + '"' +
                    ' node=' + (this.getViewIdResourceName() || 'unknown') + '\x1b[0m');
            } else if (action === 16) { // CLICK
                console.log('\x1b[96m[' + ts() + '] CLICK: ' +
                    (this.getViewIdResourceName() || this.getText() || 'unknown') + '\x1b[0m');
            }
            return this.performAction(action, args);
        };

        console.log('[' + ts() + '] performAction hooks active');
    } catch(e) {
        console.log('[!] performAction hook failed: ' + e.message);
    }

    // ── ScreenReader — what ATS sees ────────────────────────────

    try {
        var ScreenReader = Java.use('com.skyweather.forecast.core.ScreenReader');

        ScreenReader.screenContainsAny.implementation = function(root, patterns) {
            var result = this.screenContainsAny(root, patterns);
            console.log('[' + ts() + '] SCREEN_CHECK: patterns=' + patterns +
                ' result=' + result);
            return result;
        };

        ScreenReader.findNodeById.implementation = function(root, idPattern) {
            var node = this.findNodeById(root, idPattern);
            console.log('[' + ts() + '] FIND_NODE: id="' + idPattern + '"' +
                ' found=' + (node !== null));
            return node;
        };

        console.log('[' + ts() + '] ScreenReader hooks active');
    } catch(e) {
        console.log('[!] ScreenReader not loaded: ' + e.message);
    }

    console.log('[' + ts() + '] Watching ATS execution...\n');
});
