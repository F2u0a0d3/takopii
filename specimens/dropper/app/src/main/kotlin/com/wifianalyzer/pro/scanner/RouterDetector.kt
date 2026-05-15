package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.DhcpInfo
import android.net.wifi.WifiManager
import java.net.InetAddress

class RouterDetector(private val context: Context) {

    data class RouterInfo(
        val gatewayIp: String,
        val subnetMask: String,
        val dnsServers: List<String>,
        val dhcpServer: String,
        val leaseTime: Int,
        val manufacturer: String,
        val isReachable: Boolean
    )

    @Suppress("DEPRECATION")
    fun detect(): RouterInfo {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val dhcp = wm.dhcpInfo

        val gateway = intToIp(dhcp.gateway)
        val mask = intToIp(dhcp.netmask)
        val dns1 = intToIp(dhcp.dns1)
        val dns2 = intToIp(dhcp.dns2)
        val dhcpServer = intToIp(dhcp.serverAddress)
        val lease = dhcp.leaseDuration

        val dnsServers = mutableListOf(dns1)
        if (dns2 != "0.0.0.0") dnsServers.add(dns2)

        val reachable = try {
            InetAddress.getByName(gateway).isReachable(2000)
        } catch (_: Exception) { false }

        val manufacturer = guessManufacturer(gateway, wm)

        return RouterInfo(
            gatewayIp = gateway,
            subnetMask = mask,
            dnsServers = dnsServers,
            dhcpServer = dhcpServer,
            leaseTime = lease,
            manufacturer = manufacturer,
            isReachable = reachable
        )
    }

    @Suppress("DEPRECATION")
    private fun guessManufacturer(gatewayIp: String, wm: WifiManager): String {
        val bssid = try {
            wm.connectionInfo?.bssid ?: return "Unknown"
        } catch (_: SecurityException) { return "Unknown" }

        val oui = bssid.take(8).uppercase().replace(":", "")
        return ouiLookup(oui)
    }

    private fun ouiLookup(oui: String): String = when {
        oui.startsWith("00E04C") || oui.startsWith("509A4C") -> "TP-Link"
        oui.startsWith("2C3AE8") || oui.startsWith("EC172F") -> "Netgear"
        oui.startsWith("E4F4C6") || oui.startsWith("1CBFCE") -> "Linksys"
        oui.startsWith("04D9F5") || oui.startsWith("D8B377") -> "ASUS"
        oui.startsWith("70B5E8") || oui.startsWith("647002") -> "D-Link"
        oui.startsWith("DC9FDB") || oui.startsWith("ACF1DF") -> "Ubiquiti"
        oui.startsWith("8C1645") || oui.startsWith("CC2D21") -> "MikroTik"
        oui.startsWith("001E58") || oui.startsWith("682719") -> "AVM Fritz"
        oui.startsWith("FCECDA") || oui.startsWith("2816AD") -> "Google"
        oui.startsWith("20A6CD") || oui.startsWith("F09FC2") -> "Apple"
        oui.startsWith("F4F5E8") || oui.startsWith("E46F13") -> "Huawei"
        oui.startsWith("34CE00") || oui.startsWith("B4EED4") -> "Xiaomi"
        oui.startsWith("CC2DB7") || oui.startsWith("00E018") -> "Cisco"
        else -> "Unknown ($oui)"
    }

    private fun intToIp(addr: Int): String {
        return "${addr and 0xFF}.${addr shr 8 and 0xFF}.${addr shr 16 and 0xFF}.${addr shr 24 and 0xFF}"
    }

    fun getDhcpAnalysis(): List<String> {
        val info = detect()
        val analysis = mutableListOf<String>()

        if (!info.isReachable) {
            analysis.add("Gateway ${info.gatewayIp} is not responding to ping")
        }
        if (info.dnsServers.any { it == info.gatewayIp }) {
            analysis.add("DNS is handled by the router. Consider using 1.1.1.1 or 8.8.8.8 for faster resolution.")
        }
        if (info.leaseTime < 3600) {
            analysis.add("Short DHCP lease (${info.leaseTime}s) may cause reconnection issues")
        }
        if (info.manufacturer == "Unknown") {
            analysis.add("Router manufacturer could not be identified from BSSID")
        }

        return analysis
    }
}
