package com.wifianalyzer.pro.scanner

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

data class ScanRecord(
    val timestamp: Long,
    val ssid: String,
    val bssid: String,
    val level: Int,
    val channel: Int,
    val security: String
)

class WifiHistoryTracker(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("wifi_history", Context.MODE_PRIVATE)

    fun recordScan(networks: List<WifiNetwork>) {
        val ts = System.currentTimeMillis()
        val arr = JSONArray()
        for (net in networks.take(20)) {
            arr.put(JSONObject().apply {
                put("ts", ts)
                put("ssid", net.ssid)
                put("bssid", net.bssid)
                put("level", net.level)
                put("channel", net.channel)
                put("security", net.capabilities)
            })
        }
        val history = getHistory().toMutableList()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            history.add(ScanRecord(
                o.getLong("ts"), o.getString("ssid"), o.getString("bssid"),
                o.getInt("level"), o.getInt("channel"), o.getString("security")
            ))
        }
        if (history.size > 500) {
            val trimmed = history.takeLast(500)
            saveHistory(trimmed)
        } else {
            saveHistory(history)
        }
    }

    fun getHistory(): List<ScanRecord> {
        val json = prefs.getString("records", "[]") ?: "[]"
        val arr = JSONArray(json)
        val list = mutableListOf<ScanRecord>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            list.add(ScanRecord(
                o.getLong("ts"), o.getString("ssid"), o.getString("bssid"),
                o.getInt("level"), o.getInt("channel"), o.getString("security")
            ))
        }
        return list
    }

    private fun saveHistory(records: List<ScanRecord>) {
        val arr = JSONArray()
        for (r in records) {
            arr.put(JSONObject().apply {
                put("ts", r.timestamp)
                put("ssid", r.ssid)
                put("bssid", r.bssid)
                put("level", r.level)
                put("channel", r.channel)
                put("security", r.security)
            })
        }
        prefs.edit().putString("records", arr.toString()).apply()
    }

    fun getScanCount(): Int = prefs.getInt("scan_count", 0)

    fun incrementScanCount() {
        prefs.edit().putInt("scan_count", getScanCount() + 1).apply()
    }

    fun clearHistory() {
        prefs.edit().remove("records").remove("scan_count").apply()
    }

    fun getUniqueNetworkCount(): Int = getHistory().map { it.bssid }.distinct().size
}
