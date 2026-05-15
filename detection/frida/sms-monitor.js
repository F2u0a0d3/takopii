/**
 * Takopii — SMS ContentResolver Monitor
 *
 * Catches sms-stealer's DataCollector.collectRecentItems()
 * and overlay-banker's SMS reads via ContentResolver query.
 *
 * Hook 1: ContentResolver SMS query detection
 *
 * Usage: frida -U -l sms-monitor.js -f com.target.package
 */

// Hook 1: ContentResolver SMS Monitor
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
        '[Ljava.lang.String;', 'java.lang.String'
    ).implementation = function(uri, proj, sel, selArgs, sort) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
            console.log("[ALERT] SMS ContentResolver query from: " +
                Java.use("android.app.ActivityThread").currentApplication()
                    .getApplicationContext().getPackageName());
            console.log("  URI: " + uriStr);
            console.log("  Projection: " + (proj ? proj.join(", ") : "null"));
            console.log("  Sort: " + sort);
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.query(uri, proj, sel, selArgs, sort);
    };
});
