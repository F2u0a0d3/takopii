/**
 * Takopii — WindowManager Overlay Creation Monitor
 *
 * Catches OverlayAttack and OverlayRenderer overlay creation.
 * Detects both TYPE_APPLICATION_OVERLAY (2038) and
 * TYPE_ACCESSIBILITY_OVERLAY (2032) window types.
 *
 * Hook 3: WindowManager overlay creation
 *
 * Usage: frida -U -l overlay-monitor.js -f com.target.package
 */

// Hook 3: WindowManager Overlay Monitor
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
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.addView(view, params);
    };
});
