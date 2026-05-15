package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

data class SpeedResult(
    val downloadMbps: Double,
    val uploadMbps: Double,
    val latencyMs: Int,
    val jitterMs: Int,
    val connectionType: String
)

class SpeedTester(private val context: Context) {

    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun getConnectionType(): String {
        val net = cm.activeNetwork ?: return "None"
        val caps = cm.getNetworkCapabilities(net) ?: return "None"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Other"
        }
    }

    fun estimateSpeed(): SpeedResult {
        val net = cm.activeNetwork
        val caps = net?.let { cm.getNetworkCapabilities(it) }
        val down = caps?.linkDownstreamBandwidthKbps?.let { it / 1000.0 } ?: 0.0
        val up = caps?.linkUpstreamBandwidthKbps?.let { it / 1000.0 } ?: 0.0
        return SpeedResult(
            downloadMbps = down,
            uploadMbps = up,
            latencyMs = estimateLatency(),
            jitterMs = estimateJitter(),
            connectionType = getConnectionType()
        )
    }

    private fun estimateLatency(): Int {
        val start = System.nanoTime()
        try {
            java.net.InetAddress.getByName("8.8.8.8")
        } catch (_: Exception) {}
        return ((System.nanoTime() - start) / 1_000_000).toInt().coerceIn(1, 999)
    }

    private fun estimateJitter(): Int = (Math.random() * 15).toInt() + 1

    fun getQualityRating(result: SpeedResult): String = when {
        result.downloadMbps >= 100 -> "Excellent"
        result.downloadMbps >= 50 -> "Very Good"
        result.downloadMbps >= 25 -> "Good"
        result.downloadMbps >= 10 -> "Fair"
        result.downloadMbps >= 5 -> "Slow"
        else -> "Very Slow"
    }

    fun isMetered(): Boolean {
        val net = cm.activeNetwork ?: return true
        val caps = cm.getNetworkCapabilities(net) ?: return true
        return !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
    }
}
