package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

data class BandwidthInfo(
    val downstreamKbps: Int,
    val upstreamKbps: Int,
    val downstreamMbps: Double,
    val upstreamMbps: Double,
    val rating: String,
    val suitable: Map<String, Boolean>
)

class BandwidthEstimator(private val context: Context) {

    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun estimate(): BandwidthInfo {
        val net = cm.activeNetwork
        val caps = net?.let { cm.getNetworkCapabilities(it) }
        val down = caps?.linkDownstreamBandwidthKbps ?: 0
        val up = caps?.linkUpstreamBandwidthKbps ?: 0
        val downMbps = down / 1000.0
        val upMbps = up / 1000.0
        val rating = rateConnection(downMbps)
        val suitable = checkSuitability(downMbps, upMbps)
        return BandwidthInfo(down, up, downMbps, upMbps, rating, suitable)
    }

    private fun rateConnection(downMbps: Double): String = when {
        downMbps >= 100 -> "Excellent"
        downMbps >= 50 -> "Very Good"
        downMbps >= 25 -> "Good"
        downMbps >= 10 -> "Fair"
        downMbps >= 5 -> "Slow"
        else -> "Very Slow"
    }

    private fun checkSuitability(down: Double, up: Double): Map<String, Boolean> = mapOf(
        "Video Call" to (down >= 5 && up >= 2),
        "4K Streaming" to (down >= 25),
        "HD Streaming" to (down >= 10),
        "Online Gaming" to (down >= 15 && up >= 5),
        "Web Browsing" to (down >= 1),
        "Email" to (down >= 0.5)
    )
}
