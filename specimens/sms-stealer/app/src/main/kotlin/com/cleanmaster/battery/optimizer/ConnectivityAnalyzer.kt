package com.cleanmaster.battery.optimizer

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.TelephonyManager

class ConnectivityAnalyzer(private val context: Context) {

    data class ConnectionReport(
        val type: String,
        val isConnected: Boolean,
        val isMetered: Boolean,
        val downstreamBandwidthKbps: Int,
        val upstreamBandwidthKbps: Int,
        val signalStrength: String,
        val carrierName: String,
        val batteryImpact: String
    )

    fun analyze(): ConnectionReport {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = network?.let { cm.getNetworkCapabilities(it) }
        val info = cm.activeNetworkInfo

        val type = when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WiFi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> getCellularType()
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) == true -> "Bluetooth"
            else -> "Disconnected"
        }

        val down = caps?.linkDownstreamBandwidthKbps ?: 0
        val up = caps?.linkUpstreamBandwidthKbps ?: 0

        val isMetered = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cm.isActiveNetworkMetered
        } else { info?.isRoaming ?: false }

        val carrier = try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            tm.networkOperatorName ?: "Unknown"
        } catch (_: Exception) { "Unknown" }

        val signal = when {
            down > 50000 -> "Excellent"
            down > 10000 -> "Good"
            down > 2000 -> "Fair"
            down > 0 -> "Weak"
            else -> "None"
        }

        val impact = when (type) {
            "WiFi" -> "Low - WiFi uses minimal battery"
            "5G" -> "High - 5G modem consumes significant power"
            "4G/LTE" -> "Medium - cellular radio draws moderate power"
            "3G" -> "Medium-High - older radio tech less efficient"
            else -> "Minimal - no active connection"
        }

        return ConnectionReport(
            type = type,
            isConnected = caps != null,
            isMetered = isMetered,
            downstreamBandwidthKbps = down,
            upstreamBandwidthKbps = up,
            signalStrength = signal,
            carrierName = carrier,
            batteryImpact = impact
        )
    }

    private fun getCellularType(): String {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return when (tm.dataNetworkType) {
            TelephonyManager.NETWORK_TYPE_NR -> "5G"
            TelephonyManager.NETWORK_TYPE_LTE -> "4G/LTE"
            TelephonyManager.NETWORK_TYPE_HSPAP,
            TelephonyManager.NETWORK_TYPE_HSUPA,
            TelephonyManager.NETWORK_TYPE_HSDPA -> "3G+"
            TelephonyManager.NETWORK_TYPE_UMTS -> "3G"
            TelephonyManager.NETWORK_TYPE_EDGE -> "2G/EDGE"
            TelephonyManager.NETWORK_TYPE_GPRS -> "2G/GPRS"
            else -> "Cellular"
        }
    }

    fun getNetworkOptimizationTips(): List<String> {
        val report = analyze()
        val tips = mutableListOf<String>()

        if (report.type.startsWith("5G")) {
            tips.add("5G consumes more battery than WiFi. Switch to WiFi when available.")
        }
        if (report.isMetered) {
            tips.add("Metered connection detected. Background data sync uses both data and battery.")
        }
        if (report.signalStrength == "Weak") {
            tips.add("Weak signal increases radio power usage. Move closer to the router or cell tower.")
        }
        if (!report.isConnected) {
            tips.add("Enable airplane mode when connectivity isn't needed to save battery.")
        }

        tips.add("WiFi scanning in the background consumes battery even when not connected.")
        tips.add("Disable mobile data when on WiFi to prevent background cellular usage.")

        return tips
    }
}
