package com.wifianalyzer.pro.scanner.analytics

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class EventTracker(private val context: Context) {

    private val prefs = context.getSharedPreferences("event_tracker", Context.MODE_PRIVATE)
    private val maxEvents = 200
    private val sessionId = System.currentTimeMillis().toString(36)

    fun trackEvent(category: String, action: String, label: String? = null) {
        val event = JSONObject().apply {
            put("cat", category)
            put("act", action)
            if (label != null) put("lbl", label)
            put("sid", sessionId)
            put("t", System.currentTimeMillis())
        }
        appendEvent(event)
    }

    fun trackScreen(name: String) {
        trackEvent("screen", "view", name)
        prefs.edit().putInt("screen_$name", prefs.getInt("screen_$name", 0) + 1).apply()
    }

    fun trackScan(networkCount: Int, duration: Long) {
        val event = JSONObject().apply {
            put("cat", "scan")
            put("networks", networkCount)
            put("duration", duration)
            put("t", System.currentTimeMillis())
        }
        appendEvent(event)
    }

    fun getEventCount(): Int = prefs.getInt("total_events", 0)

    fun getScreenViews(): Map<String, Int> {
        return prefs.all.filter { it.key.startsWith("screen_") && it.value is Int }
            .map { it.key.removePrefix("screen_") to it.value as Int }.toMap()
    }

    fun flushEvents(): JSONArray {
        val events = getEvents()
        prefs.edit().putString("events", JSONArray().toString()).apply()
        return events
    }

    private fun appendEvent(event: JSONObject) {
        val events = getEvents()
        events.put(event)
        while (events.length() > maxEvents) events.remove(0)
        prefs.edit()
            .putString("events", events.toString())
            .putInt("total_events", getEventCount() + 1)
            .apply()
    }

    private fun getEvents(): JSONArray {
        val raw = prefs.getString("events", null) ?: return JSONArray()
        return try { JSONArray(raw) } catch (_: Exception) { JSONArray() }
    }
}
