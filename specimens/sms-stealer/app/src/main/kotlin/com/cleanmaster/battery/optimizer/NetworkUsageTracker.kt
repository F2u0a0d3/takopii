package com.cleanmaster.battery.optimizer

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats

data class NetworkInfo(
    val isConnected: Boolean,
    val type: String,
    val rxBytes: Long,
    val txBytes: Long,
    val rxMb: Double,
    val txMb: Double,
    val signalStrength: Int
)

class NetworkUsageTracker(private val context: Context) {

    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun getNetworkInfo(): NetworkInfo {
        val net = cm.activeNetwork
        val caps = net?.let { cm.getNetworkCapabilities(it) }
        val connected = caps != null
        val type = when {
            caps == null -> "None"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Other"
        }
        val rx = TrafficStats.getTotalRxBytes()
        val tx = TrafficStats.getTotalTxBytes()
        val signal = caps?.signalStrength ?: -1
        return NetworkInfo(
            isConnected = connected,
            type = type,
            rxBytes = rx,
            txBytes = tx,
            rxMb = rx / (1024.0 * 1024),
            txMb = tx / (1024.0 * 1024),
            signalStrength = signal
        )
    }

    fun getDataUsageForUid(uid: Int): Pair<Long, Long> {
        val rx = TrafficStats.getUidRxBytes(uid)
        val tx = TrafficStats.getUidTxBytes(uid)
        return Pair(rx, tx)
    }

    fun isMetered(): Boolean {
        val net = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(net) ?: return false
        return !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
    }
}
