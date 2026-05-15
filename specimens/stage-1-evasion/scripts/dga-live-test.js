/*
 * DGA Live Test — Frida hook for DomainResolver fallback verification.
 *
 * Handles Kotlin `object` singleton pattern — calls via INSTANCE field.
 *
 * Usage:
 *   frida -U -n com.skyweather.forecast -l dga-live-test.js
 */
"use strict";

Java.perform(function () {
    var TAG = "[DGA-TEST]";
    var testResults = {
        algorithmMatch: false,
        allRfc1918: false,
        primaryFailed: false,
        dgaCandidatesGenerated: false,
        silentFailure: false,
        callSequenceCorrect: false
    };

    console.log(TAG + " =============================================");
    console.log(TAG + " DGA FALLBACK LIVE TEST");
    console.log(TAG + " =============================================");

    var DRClass = Java.use("com.skyweather.forecast.core.DomainResolver");
    var ACClass = Java.use("com.skyweather.forecast.core.AppConfig");

    // Kotlin object → static INSTANCE field
    var DR = DRClass.INSTANCE.value;
    var AC = ACClass.INSTANCE.value;

    // ─── TEST 1: Algorithm output verification ──────────────────────
    console.log(TAG + "");
    console.log(TAG + " --- TEST 1: generateFallbacks() output ---");

    var fallbacks = DR.generateFallbacks();
    var count = fallbacks.size();
    console.log(TAG + " Generated " + count + " DGA candidates:");

    var allPrivate = true;
    for (var i = 0; i < count; i++) {
        var ep = fallbacks.get(i).toString();
        console.log(TAG + "   [" + i + "] " + ep);

        var hostMatch = ep.match(/http:\/\/([\d.]+):/);
        if (hostMatch) {
            var host = hostMatch[1];
            if (!host.startsWith("10.")) {
                console.log(TAG + "   !! NOT RFC1918: " + host);
                allPrivate = false;
            }
        }
    }
    testResults.dgaCandidatesGenerated = (count === 4);
    testResults.allRfc1918 = allPrivate;
    console.log(TAG + " Candidates: " + count + "/4 " + (count === 4 ? "PASS" : "FAIL"));
    console.log(TAG + " All RFC1918: " + (allPrivate ? "PASS" : "FAIL"));

    // ─── TEST 2: Primary endpoint decode ────────────────────────────
    console.log(TAG + "");
    console.log(TAG + " --- TEST 2: Primary endpoint ---");

    var primary = AC.endpoint();
    console.log(TAG + " AppConfig.endpoint() = " + primary);

    var isSafe = AC.isEndpointSafe();
    console.log(TAG + " isEndpointSafe() = " + isSafe);

    // ─── TEST 3: Force DGA path — hook isReachable ──────────────────
    console.log(TAG + "");
    console.log(TAG + " --- TEST 3: resolveEndpoint() with primary FORCED DOWN ---");

    var callCount = 0;
    var rfc1918Checks = 0;

    // Hook instance methods via the class
    DRClass.isReachable.implementation = function (endpoint) {
        callCount++;
        var ep = endpoint.toString();

        if (ep === primary) {
            console.log(TAG + " isReachable(" + ep + ") => false [FORCED]");
            testResults.primaryFailed = true;
            return false;
        }

        // DGA candidates: let them try (should fail — nothing listening at 10.x.y.z)
        var result = this.isReachable(endpoint);
        console.log(TAG + " isReachable(" + ep + ") => " + result + " [natural]");
        return result;
    };

    DRClass.isRfc1918.implementation = function (endpoint) {
        rfc1918Checks++;
        var result = this.isRfc1918(endpoint);
        console.log(TAG + " isRfc1918(" + endpoint + ") => " + result);
        return result;
    };

    DRClass.md5Hex.implementation = function (input) {
        var result = this.md5Hex(input);
        console.log(TAG + " md5Hex(" + input + ") => " + result);
        return result;
    };

    // Call resolveEndpoint() — primary fails -> DGA -> all fail -> null
    console.log(TAG + "");
    console.log(TAG + " Calling resolveEndpoint() ...");
    var resolved = DR.resolveEndpoint();
    console.log(TAG + "");
    console.log(TAG + " resolveEndpoint() => " + resolved);

    testResults.silentFailure = (resolved === null);
    testResults.callSequenceCorrect = (callCount === 5);

    // ─── TEST 4: Call sequence ──────────────────────────────────────
    console.log(TAG + "");
    console.log(TAG + " --- TEST 4: Call sequence ---");
    console.log(TAG + " isReachable() calls: " + callCount + " (expected 5: 1 primary + 4 DGA)");
    console.log(TAG + " isRfc1918() calls:   " + rfc1918Checks + " (expected 4: one per DGA candidate)");
    console.log(TAG + " Sequence: " + (callCount === 5 ? "PASS" : "FAIL"));

    // ─── TEST 5: Week/year seed ─────────────────────────────────────
    console.log(TAG + "");
    console.log(TAG + " --- TEST 5: Calendar seed ---");

    var Calendar = Java.use("java.util.Calendar");
    var cal = Calendar.getInstance();
    var week = cal.get(3);  // WEEK_OF_YEAR = 3
    var year = cal.get(1);  // YEAR = 1
    console.log(TAG + " Java Calendar: week=" + week + " year=" + year);
    console.log(TAG + " Cross-check: verify-dga.py should show same week/year");

    // ─── SUMMARY ────────────────────────────────────────────────────
    console.log(TAG + "");
    console.log(TAG + " =============================================");
    console.log(TAG + " TEST RESULTS");
    console.log(TAG + " =============================================");
    console.log(TAG + " [1] DGA candidates (4):     " + (testResults.dgaCandidatesGenerated ? "PASS" : "FAIL"));
    console.log(TAG + " [2] All RFC1918:             " + (testResults.allRfc1918 ? "PASS" : "FAIL"));
    console.log(TAG + " [3] Primary forced fail:     " + (testResults.primaryFailed ? "PASS" : "FAIL"));
    console.log(TAG + " [4] Silent null return:      " + (testResults.silentFailure ? "PASS" : "FAIL"));
    console.log(TAG + " [5] Call sequence (5 calls): " + (testResults.callSequenceCorrect ? "PASS" : "FAIL"));

    var allPass = testResults.dgaCandidatesGenerated &&
                  testResults.allRfc1918 &&
                  testResults.primaryFailed &&
                  testResults.silentFailure &&
                  testResults.callSequenceCorrect;

    console.log(TAG + " =============================================");
    console.log(TAG + " OVERALL: " + (allPass ? "ALL TESTS PASSED" : "SOME TESTS FAILED"));
    console.log(TAG + " =============================================");

    // Restore hooks
    DRClass.isReachable.implementation = null;
    DRClass.isRfc1918.implementation = null;
    DRClass.md5Hex.implementation = null;
});
