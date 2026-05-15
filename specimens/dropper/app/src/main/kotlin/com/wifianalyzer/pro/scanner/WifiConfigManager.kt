package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.wifi.WifiManager

class WifiConfigManager(private val context: Context) {

    data class WifiState(
        val isEnabled: Boolean,
        val isScanAlwaysAvailable: Boolean,
        val is5GhzSupported: Boolean,
        val wifiStandard: String,
        val macAddress: String,
        val ipAddress: String,
        val frequency: Int,
        val linkSpeed: Int,
        val txLinkSpeed: Int,
        val rxLinkSpeed: Int
    )

    @Suppress("DEPRECATION")
    fun getWifiState(): WifiState {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = try { wm.connectionInfo } catch (_: SecurityException) { null }

        val is5Ghz = try { wm.is5GHzBandSupported } catch (_: Exception) { false }
        val scanAlways = wm.isScanAlwaysAvailable

        return WifiState(
            isEnabled = wm.isWifiEnabled,
            isScanAlwaysAvailable = scanAlways,
            is5GhzSupported = is5Ghz,
            wifiStandard = detectWifiStandard(info?.linkSpeed ?: 0, info?.frequency ?: 0),
            macAddress = "XX:XX:XX:XX:XX:XX",
            ipAddress = info?.let { intToIp(it.ipAddress) } ?: "0.0.0.0",
            frequency = info?.frequency ?: 0,
            linkSpeed = info?.linkSpeed ?: 0,
            txLinkSpeed = try { info?.txLinkSpeedMbps ?: 0 } catch (_: Exception) { 0 },
            rxLinkSpeed = try { info?.rxLinkSpeedMbps ?: 0 } catch (_: Exception) { 0 }
        )
    }

    private fun detectWifiStandard(linkSpeed: Int, freq: Int): String = when {
        linkSpeed > 1200 && freq > 5925 -> "WiFi 6E (802.11ax)"
        linkSpeed > 600 -> "WiFi 6 (802.11ax)"
        linkSpeed > 300 && freq > 4900 -> "WiFi 5 (802.11ac)"
        linkSpeed > 72 -> "WiFi 4 (802.11n)"
        linkSpeed > 11 -> "WiFi 3 (802.11g)"
        else -> "WiFi 1/2 (802.11b)"
    }

    fun getWifiDiagnostics(): List<String> {
        val state = getWifiState()
        val diagnostics = mutableListOf<String>()

        if (!state.isEnabled) {
            diagnostics.add("WiFi is currently disabled")
            return diagnostics
        }

        if (!state.is5GhzSupported) {
            diagnostics.add("Device does not support 5 GHz band - only 2.4 GHz available")
        }
        if (state.linkSpeed < 72) {
            diagnostics.add("Low link speed (${state.linkSpeed} Mbps) - possible interference or distance issue")
        }
        if (state.frequency in 2400..2500 && state.is5GhzSupported) {
            diagnostics.add("Connected on 2.4 GHz but 5 GHz is supported - consider switching for better speed")
        }
        if (state.isScanAlwaysAvailable) {
            diagnostics.add("WiFi scanning is always available - this uses battery even when WiFi is off")
        }

        diagnostics.add("WiFi standard: ${state.wifiStandard}")
        diagnostics.add("Connection: ${state.linkSpeed} Mbps on ${state.frequency} MHz")

        return diagnostics
    }

    private fun intToIp(addr: Int): String {
        return "${addr and 0xFF}.${addr shr 8 and 0xFF}.${addr shr 16 and 0xFF}.${addr shr 24 and 0xFF}"
    }
}
