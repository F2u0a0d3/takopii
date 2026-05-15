package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.NetworkCapabilities
import android.os.Build
import java.net.InetAddress

data class DiagnosticResult(
    val internetReachable: Boolean,
    val dnsResolves: Boolean,
    val gatewayReachable: Boolean,
    val ipv6Available: Boolean,
    val captivePortal: Boolean,
    val issues: List<String>
)

class NetworkDiagnostics(private val context: Context) {

    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun runDiagnostics(): DiagnosticResult {
        val issues = mutableListOf<String>()
        val internet = checkInternet()
        val dns = checkDns()
        val gateway = checkGateway()
        val ipv6 = checkIpv6()
        val captive = checkCaptivePortal()

        if (!internet) issues.add("No internet connectivity detected")
        if (!dns) issues.add("DNS resolution failing")
        if (!gateway) issues.add("Default gateway unreachable")
        if (captive) issues.add("Captive portal detected — may need to sign in")
        if (!ipv6) issues.add("IPv6 not available on this network")

        return DiagnosticResult(internet, dns, gateway, ipv6, captive, issues)
    }

    private fun checkInternet(): Boolean {
        val net = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(net) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private fun checkDns(): Boolean {
        return try {
            InetAddress.getByName("dns.google")
            true
        } catch (_: Exception) { false }
    }

    private fun checkGateway(): Boolean {
        return try {
            val gw = InetAddress.getByName("192.168.1.1")
            gw.isReachable(2000)
        } catch (_: Exception) { false }
    }

    private fun checkIpv6(): Boolean {
        return try {
            val addrs = InetAddress.getAllByName("dns.google")
            addrs.any { it is java.net.Inet6Address }
        } catch (_: Exception) { false }
    }

    private fun checkCaptivePortal(): Boolean {
        val net = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(net) ?: return false
        return !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
    }

    fun getStatusSummary(): String {
        val result = runDiagnostics()
        return if (result.issues.isEmpty()) "All checks passed" else result.issues.joinToString("; ")
    }
}
