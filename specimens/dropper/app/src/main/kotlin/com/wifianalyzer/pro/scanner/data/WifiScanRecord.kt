package com.wifianalyzer.pro.scanner.data

data class WifiScanRecord(
    val id: Long = 0,
    val timestamp: Long,
    val networkCount: Int,
    val bestSignalDbm: Int,
    val avgSignalDbm: Int,
    val connectedSsid: String,
    val connectedBssid: String
) {
    fun signalQuality(): String = when {
        bestSignalDbm >= -50 -> "Excellent"
        bestSignalDbm >= -60 -> "Good"
        bestSignalDbm >= -70 -> "Fair"
        bestSignalDbm >= -80 -> "Weak"
        else -> "Very Weak"
    }

    fun signalPercent(): Int = ((bestSignalDbm + 100).coerceIn(0, 60) * 100 / 60)

    fun isConnected(): Boolean = connectedSsid.isNotEmpty()
}

data class NetworkRecord(
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val frequency: Int,
    val channel: Int,
    val security: String,
    val channelWidth: String = ""
) {
    fun isOpen(): Boolean = security.contains("Open", true) || security.isEmpty()
    fun is5Ghz(): Boolean = frequency > 4900
    fun is6Ghz(): Boolean = frequency > 5925

    fun band(): String = when {
        is6Ghz() -> "6 GHz"
        is5Ghz() -> "5 GHz"
        else -> "2.4 GHz"
    }

    fun signalBars(): Int = when {
        rssi >= -55 -> 4
        rssi >= -66 -> 3
        rssi >= -77 -> 2
        rssi >= -88 -> 1
        else -> 0
    }

    fun securityRating(): String = when {
        security.contains("WPA3", true) -> "Strong"
        security.contains("WPA2", true) -> "Good"
        security.contains("WPA", true) -> "Fair"
        security.contains("WEP", true) -> "Weak"
        isOpen() -> "None"
        else -> "Unknown"
    }
}

data class PreferencesState(
    val autoScan: Boolean = true,
    val include5Ghz: Boolean = true,
    val detectHidden: Boolean = false,
    val continuousScan: Boolean = false,
    val showSignalBars: Boolean = true,
    val showChannelInfo: Boolean = true,
    val saveHistory: Boolean = true,
    val scanIntervalSeconds: Int = 30
)
