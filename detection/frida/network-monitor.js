/**
 * Takopii — Network / HTTP Exfiltration Monitor
 *
 * Catches DataReporter.sendReport(), Exfil.flush(), C2.registerBot()
 * and all HTTP-based exfiltration via HttpURLConnection and OkHttp.
 *
 * Hook 2: HttpURLConnection POST monitor
 * Hook 7: OkHttp exfil monitor (overlay-banker)
 *
 * Usage: frida -U -l network-monitor.js -f com.target.package
 */

// Hook 2: HttpURLConnection POST Monitor
Java.perform(function() {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var URL = Java.use("java.net.URL");

    URL.$init.overload('java.lang.String').implementation = function(url) {
        console.log("[NET] URL created: " + url);
        return this.$init(url);
    };

    HttpURLConnection.setRequestMethod.implementation = function(method) {
        console.log("[NET] HTTP " + method + " -> " + this.getURL().toString());
        return this.setRequestMethod(method);
    };

    HttpURLConnection.getOutputStream.implementation = function() {
        console.log("[EXFIL] POST body being written to: " + this.getURL().toString());
        return this.getOutputStream();
    };

    // Capture response codes for dropper config check pattern
    HttpURLConnection.getResponseCode.implementation = function() {
        var code = this.getResponseCode();
        console.log("[NET] Response " + code + " from " + this.getURL().toString());
        return code;
    };
});

// Hook 7: OkHttp Exfil Monitor (overlay-banker)
Java.perform(function() {
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RequestBuilder = Java.use("okhttp3.Request$Builder");

        RequestBuilder.url.overload('java.lang.String').implementation = function(url) {
            console.log("[OKHTTP] Request URL: " + url);
            return this.url(url);
        };

        RequestBuilder.post.implementation = function(body) {
            console.log("[OKHTTP-EXFIL] POST request with body");
            try {
                var buf = Java.use("okio.Buffer").$new();
                body.writeTo(buf);
                var bodyStr = buf.readUtf8();
                if (bodyStr.length > 500) bodyStr = bodyStr.substring(0, 500) + "...";
                console.log("  Body: " + bodyStr);
            } catch(e) {}
            return this.post(body);
        };
    } catch(e) {
        console.log("[INFO] OkHttp not present in this specimen");
    }
});
