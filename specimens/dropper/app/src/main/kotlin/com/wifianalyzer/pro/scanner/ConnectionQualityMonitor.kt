package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import com.wifianalyzer.pro.scanner.util.SignalConverter

class ConnectionQualityMonitor(private val context: Context) {

    data class QualityScore(
        val overall: Int,
        val signalScore: Int,
        val speedScore: Int,
        val stabilityScore: Int,
        val securityScore: Int,
        val latencyScore: Int,
        val description: String,
        val recommendations: List<String>
    )

    @Suppress("DEPRECATION")
    fun evaluate(): QualityScore {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val wifiInfo = try { wm.connectionInfo } catch (_: SecurityException) { null }
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }

        val rssi = wifiInfo?.rssi ?: -100
        val linkSpeed = wifiInfo?.linkSpeed ?: 0
        val freq = wifiInfo?.frequency ?: 0

        val signalScore = SignalConverter.dbmToPercent(rssi)
        val speedScore = calculateSpeedScore(linkSpeed, caps)
        val stabilityScore = calculateStabilityScore(rssi)
        val securityScore = calculateSecurityScore(wm)
        val latencyScore = calculateLatencyScore(caps)

        val overall = (signalScore * 0.30 + speedScore * 0.25 +
            stabilityScore * 0.20 + securityScore * 0.15 + latencyScore * 0.10).toInt()

        val desc = when {
            overall >= 80 -> "Excellent WiFi quality"
            overall >= 60 -> "Good WiFi quality"
            overall >= 40 -> "Fair WiFi quality - some improvements possible"
            overall >= 20 -> "Poor WiFi quality - optimization recommended"
            else -> "Very poor WiFi quality - troubleshooting needed"
        }

        val recs = buildRecommendations(signalScore, speedScore, stabilityScore, securityScore, freq)

        return QualityScore(
            overall = overall,
            signalScore = signalScore,
            speedScore = speedScore,
            stabilityScore = stabilityScore,
            securityScore = securityScore,
            latencyScore = latencyScore,
            description = desc,
            recommendations = recs
        )
    }

    private fun calculateSpeedScore(linkSpeed: Int, caps: NetworkCapabilities?): Int {
        val down = caps?.linkDownstreamBandwidthKbps ?: 0
        return when {
            down > 100000 -> 100
            down > 50000 -> 80
            down > 20000 -> 60
            down > 5000 -> 40
            linkSpeed > 100 -> 50
            linkSpeed > 50 -> 30
            else -> 10
        }
    }

    private fun calculateStabilityScore(rssi: Int): Int = when {
        rssi >= -55 -> 100
        rssi >= -65 -> 80
        rssi >= -75 -> 50
        rssi >= -85 -> 25
        else -> 5
    }

    @Suppress("DEPRECATION")
    private fun calculateSecurityScore(wm: WifiManager): Int {
        val scanResults = try { wm.scanResults } catch (_: SecurityException) { null }
        val connectedBssid = try { wm.connectionInfo?.bssid } catch (_: SecurityException) { null }
        val connected = scanResults?.find { it.BSSID == connectedBssid }
        val caps = connected?.capabilities ?: return 50
        return when {
            caps.contains("WPA3") -> 100
            caps.contains("WPA2") -> 80
            caps.contains("WPA") -> 50
            caps.contains("WEP") -> 20
            else -> 0
        }
    }

    private fun calculateLatencyScore(caps: NetworkCapabilities?): Int {
        val down = caps?.linkDownstreamBandwidthKbps ?: 0
        return when {
            down > 50000 -> 90
            down > 20000 -> 70
            down > 5000 -> 50
            else -> 30
        }
    }

    private fun buildRecommendations(signal: Int, speed: Int, stability: Int, security: Int, freq: Int): List<String> {
        val recs = mutableListOf<String>()
        if (signal < 50) recs.add("Move closer to the WiFi access point for better signal")
        if (speed < 50) recs.add("Connection speed is below average. Check for bandwidth-heavy apps")
        if (stability < 50) recs.add("Connection may be unstable. Consider a WiFi repeater")
        if (security < 50) recs.add("WiFi security is weak. Upgrade to WPA2 or WPA3")
        if (freq < 4900) recs.add("You're on 2.4 GHz. 5 GHz offers less interference and faster speeds")
        if (recs.isEmpty()) recs.add("Your WiFi connection is performing well. No action needed.")
        return recs
    }
}
