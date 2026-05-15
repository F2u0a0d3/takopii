/**
 * Takopii — Clipboard Polling Detection Monitor
 *
 * Catches BankerA11yService.pollClipboard() 2500ms clipboard capture loop.
 * Detects Path 2 clipper pattern: clipboard read from AccessibilityService
 * context bypassing Android 10+ background clipboard restrictions.
 *
 * Hook 10: Clipboard polling monitor
 *
 * Usage: frida -U -l clipboard-monitor.js -f com.target.package
 */

// Hook 10: Clipboard Polling Monitor
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
                // Flag if read from AccessibilityService context
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
