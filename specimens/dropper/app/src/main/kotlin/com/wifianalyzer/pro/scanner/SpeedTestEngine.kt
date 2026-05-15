package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

class SpeedTestEngine(private val context: Context) {

    private val prefs = context.getSharedPreferences("speed_tests", Context.MODE_PRIVATE)

    fun estimateSpeed(): SpeedEstimate {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = if (network != null) cm.getNetworkCapabilities(network) else null

        val downKbps = caps?.linkDownstreamBandwidthKbps ?: 0
        val upKbps = caps?.linkUpstreamBandwidthKbps ?: 0

        return SpeedEstimate(
            downloadMbps = downKbps / 1000.0,
            uploadMbps = upKbps / 1000.0,
            quality = when {
                downKbps > 50000 -> "Excellent"
                downKbps > 25000 -> "Good"
                downKbps > 10000 -> "Fair"
                downKbps > 5000 -> "Slow"
                else -> "Very Slow"
            }
        )
    }

    fun saveResult(result: SpeedEstimate) {
        val count = prefs.getInt("test_count", 0)
        prefs.edit()
            .putFloat("dl_$count", result.downloadMbps.toFloat())
            .putFloat("ul_$count", result.uploadMbps.toFloat())
            .putLong("time_$count", System.currentTimeMillis())
            .putInt("test_count", count + 1)
            .apply()
    }

    fun getHistory(): List<SpeedEstimate> {
        val count = prefs.getInt("test_count", 0)
        return (0 until count.coerceAtMost(50)).map { i ->
            SpeedEstimate(
                downloadMbps = prefs.getFloat("dl_$i", 0f).toDouble(),
                uploadMbps = prefs.getFloat("ul_$i", 0f).toDouble(),
                quality = "",
                timestamp = prefs.getLong("time_$i", 0L)
            )
        }
    }

    fun getAverageSpeed(): SpeedEstimate {
        val history = getHistory()
        if (history.isEmpty()) return SpeedEstimate(0.0, 0.0, "No data")
        return SpeedEstimate(
            downloadMbps = history.map { it.downloadMbps }.average(),
            uploadMbps = history.map { it.uploadMbps }.average(),
            quality = "Average"
        )
    }

    data class SpeedEstimate(
        val downloadMbps: Double,
        val uploadMbps: Double,
        val quality: String,
        val timestamp: Long = System.currentTimeMillis()
    )
}
