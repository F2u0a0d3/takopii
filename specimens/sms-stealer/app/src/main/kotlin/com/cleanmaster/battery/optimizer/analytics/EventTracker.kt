package com.cleanmaster.battery.optimizer.analytics

import android.content.Context
import android.os.Bundle
import org.json.JSONArray
import org.json.JSONObject

class EventTracker(private val context: Context) {

    private val prefs = context.getSharedPreferences("event_tracker", Context.MODE_PRIVATE)
    private val maxQueueSize = 100
    private val sessionId = System.currentTimeMillis().toString(36)

    fun trackEvent(category: String, action: String, label: String? = null, value: Long? = null) {
        val event = JSONObject().apply {
            put("cat", category)
            put("act", action)
            if (label != null) put("lbl", label)
            if (value != null) put("val", value)
            put("sid", sessionId)
            put("t", System.currentTimeMillis())
        }
        appendToQueue(event)
    }

    fun trackScreen(screenName: String) {
        trackEvent("screen", "view", screenName)
        val screenCounts = prefs.getInt("screen_$screenName", 0)
        prefs.edit().putInt("screen_$screenName", screenCounts + 1).apply()
    }

    fun trackTiming(category: String, variable: String, durationMs: Long) {
        trackEvent("timing", variable, category, durationMs)
    }

    fun trackException(throwable: Throwable, fatal: Boolean = false) {
        val event = JSONObject().apply {
            put("cat", "exception")
            put("act", throwable.javaClass.simpleName)
            put("lbl", throwable.message ?: "unknown")
            put("fatal", fatal)
            put("t", System.currentTimeMillis())
        }
        appendToQueue(event)
    }

    fun getEventCount(): Int = prefs.getInt("total_events", 0)

    fun getSessionDuration(): Long {
        val start = prefs.getLong("session_start_$sessionId", System.currentTimeMillis())
        return System.currentTimeMillis() - start
    }

    fun getScreenViewCounts(): Map<String, Int> {
        val result = mutableMapOf<String, Int>()
        val all = prefs.all
        for ((key, value) in all) {
            if (key.startsWith("screen_") && value is Int) {
                result[key.removePrefix("screen_")] = value
            }
        }
        return result
    }

    private fun appendToQueue(event: JSONObject) {
        val queue = getQueue()
        if (queue.length() >= maxQueueSize) {
            val trimmed = JSONArray()
            for (i in queue.length() / 2 until queue.length()) {
                trimmed.put(queue.getJSONObject(i))
            }
            saveQueue(trimmed)
        } else {
            queue.put(event)
            saveQueue(queue)
        }
        prefs.edit().putInt("total_events", getEventCount() + 1).apply()
    }

    fun flushQueue(): JSONArray {
        val queue = getQueue()
        saveQueue(JSONArray())
        return queue
    }

    private fun getQueue(): JSONArray {
        val raw = prefs.getString("event_queue", null) ?: return JSONArray()
        return try { JSONArray(raw) } catch (_: Exception) { JSONArray() }
    }

    private fun saveQueue(queue: JSONArray) {
        prefs.edit().putString("event_queue", queue.toString()).apply()
    }

    fun fromBundle(bundle: Bundle): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>()
        for (key in bundle.keySet()) {
            map[key] = bundle.get(key)
        }
        return map
    }
}
