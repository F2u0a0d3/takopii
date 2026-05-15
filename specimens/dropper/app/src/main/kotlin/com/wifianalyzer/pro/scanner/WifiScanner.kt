package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.wifi.WifiManager
import android.net.wifi.ScanResult

data class WifiNetwork(
    val ssid: String,
    val bssid: String,
    val level: Int,
    val frequency: Int,
    val capabilities: String,
    val channel: Int,
    val signalQuality: Int,
    val band: String
)

class WifiScanner(private val context: Context) {

    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    fun scan(): List<WifiNetwork> {
        @Suppress("DEPRECATION")
        val results = wifiManager.scanResults ?: return emptyList()
        return results.map { mapResult(it) }.sortedByDescending { it.level }
    }

    private fun mapResult(sr: ScanResult): WifiNetwork {
        val ch = frequencyToChannel(sr.frequency)
        val band = if (sr.frequency > 5000) "5 GHz" else "2.4 GHz"
        return WifiNetwork(
            ssid = sr.SSID.ifEmpty { "<Hidden>" },
            bssid = sr.BSSID ?: "00:00:00:00:00:00",
            level = sr.level,
            frequency = sr.frequency,
            capabilities = sr.capabilities ?: "",
            channel = ch,
            signalQuality = calculateQuality(sr.level),
            band = band
        )
    }

    fun frequencyToChannel(freq: Int): Int = when {
        freq in 2412..2484 -> (freq - 2412) / 5 + 1
        freq in 5170..5825 -> (freq - 5170) / 5 + 34
        else -> 0
    }

    fun calculateQuality(rssi: Int): Int = when {
        rssi >= -30 -> 100
        rssi >= -50 -> 90
        rssi >= -60 -> 75
        rssi >= -70 -> 50
        rssi >= -80 -> 30
        rssi >= -90 -> 10
        else -> 0
    }

    fun getSecurityType(capabilities: String): String = when {
        capabilities.contains("WPA3") -> "WPA3"
        capabilities.contains("WPA2") -> "WPA2"
        capabilities.contains("WPA") -> "WPA"
        capabilities.contains("WEP") -> "WEP"
        else -> "Open"
    }

    fun getConnectionInfo(): ConnectionInfo {
        @Suppress("DEPRECATION")
        val info = wifiManager.connectionInfo
        return ConnectionInfo(
            ssid = info.ssid?.removeSurrounding("\"") ?: "",
            bssid = info.bssid ?: "",
            rssi = info.rssi,
            linkSpeed = info.linkSpeed,
            frequency = info.frequency,
            ip = intToIp(info.ipAddress)
        )
    }

    private fun intToIp(ip: Int): String {
        return "${ip and 0xFF}.${(ip shr 8) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 24) and 0xFF}"
    }
}

data class ConnectionInfo(
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val linkSpeed: Int,
    val frequency: Int,
    val ip: String
)
