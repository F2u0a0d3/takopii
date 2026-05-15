package com.wifianalyzer.pro.ui

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.wifianalyzer.pro.R

class DiagnosticsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        runDiagnostics()
    }

    private fun runDiagnostics() {
        val results = mutableListOf<DiagResult>()
        results.add(checkWifiState())
        results.add(checkConnectivity())
        results.add(checkDns())
        results.add(checkProxy())
        results.add(checkIpv6())
        results.add(checkSignalStrength())
        results.add(checkFrequencyBand())
        results.add(checkSecurityType())

        val text = results.joinToString("\n") { "${it.test}: ${it.status} — ${it.detail}" }
        findViewById<TextView>(R.id.textNetworkCount)?.text = text

        val score = results.count { it.status == "Pass" } * 100 / results.size.coerceAtLeast(1)
        saveResult(score)
    }

    @Suppress("DEPRECATION")
    private fun checkWifiState(): DiagResult {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return if (wm.isWifiEnabled) {
            DiagResult("WiFi", "Pass", "WiFi is enabled")
        } else {
            DiagResult("WiFi", "Fail", "WiFi is disabled")
        }
    }

    private fun checkConnectivity(): DiagResult {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = if (network != null) cm.getNetworkCapabilities(network) else null
        return if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            val downMbps = caps.linkDownstreamBandwidthKbps / 1000
            DiagResult("Connection", "Pass", "WiFi connected ($downMbps Mbps)")
        } else {
            DiagResult("Connection", "Fail", "Not connected to WiFi")
        }
    }

    private fun checkDns(): DiagResult {
        return try {
            val start = System.currentTimeMillis()
            java.net.InetAddress.getByName("dns.google")
            val elapsed = System.currentTimeMillis() - start
            DiagResult("DNS", "Pass", "Resolution: ${elapsed}ms")
        } catch (e: Exception) {
            DiagResult("DNS", "Fail", e.message ?: "DNS resolution failed")
        }
    }

    private fun checkProxy(): DiagResult {
        val host = System.getProperty("http.proxyHost")
        val port = System.getProperty("http.proxyPort")
        return if (host.isNullOrEmpty()) {
            DiagResult("Proxy", "Pass", "No proxy configured")
        } else {
            DiagResult("Proxy", "Info", "Proxy: $host:$port")
        }
    }

    private fun checkIpv6(): DiagResult {
        return try {
            val addresses = java.net.NetworkInterface.getNetworkInterfaces()
            var hasIpv6 = false
            while (addresses.hasMoreElements()) {
                val iface = addresses.nextElement()
                val addrs = iface.inetAddresses
                while (addrs.hasMoreElements()) {
                    val addr = addrs.nextElement()
                    if (addr is java.net.Inet6Address && !addr.isLoopbackAddress) {
                        hasIpv6 = true
                    }
                }
            }
            if (hasIpv6) DiagResult("IPv6", "Pass", "IPv6 available")
            else DiagResult("IPv6", "Info", "IPv6 not detected")
        } catch (e: Exception) {
            DiagResult("IPv6", "Fail", e.message ?: "Error")
        }
    }

    @Suppress("DEPRECATION")
    private fun checkSignalStrength(): DiagResult {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = wm.connectionInfo
        val rssi = info.rssi
        val level = WifiManager.calculateSignalLevel(rssi, 5)
        val quality = when (level) {
            4 -> "Excellent"
            3 -> "Good"
            2 -> "Fair"
            1 -> "Weak"
            else -> "Very Weak"
        }
        return DiagResult("Signal", if (level >= 2) "Pass" else "Warn", "$quality ($rssi dBm)")
    }

    @Suppress("DEPRECATION")
    private fun checkFrequencyBand(): DiagResult {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = wm.connectionInfo
        val freq = info.frequency
        val band = when {
            freq in 2400..2500 -> "2.4 GHz"
            freq in 4900..5900 -> "5 GHz"
            freq in 5925..7125 -> "6 GHz"
            else -> "Unknown"
        }
        return DiagResult("Band", "Info", "$band ($freq MHz)")
    }

    @Suppress("DEPRECATION")
    private fun checkSecurityType(): DiagResult {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = wm.connectionInfo
        val ssid = info.ssid?.replace("\"", "") ?: "Unknown"
        return DiagResult("Network", "Info", ssid)
    }

    private fun saveResult(score: Int) {
        val prefs = getSharedPreferences("diagnostics", MODE_PRIVATE)
        prefs.edit()
            .putInt("last_score", score)
            .putLong("last_run", System.currentTimeMillis())
            .putInt("run_count", prefs.getInt("run_count", 0) + 1)
            .apply()
    }

    data class DiagResult(val test: String, val status: String, val detail: String)
}
