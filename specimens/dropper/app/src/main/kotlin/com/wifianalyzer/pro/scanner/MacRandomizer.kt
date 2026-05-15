package com.wifianalyzer.pro.scanner

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build

class MacRandomizer(private val context: Context) {

    @Suppress("DEPRECATION")
    fun getCurrentMac(): String {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            "Randomized (Android 11+)"
        } else {
            wm.connectionInfo?.macAddress ?: "02:00:00:00:00:00"
        }
    }

    fun isRandomized(mac: String): Boolean {
        if (mac == "02:00:00:00:00:00" || mac.contains("Randomized")) return true
        val firstByte = mac.split(":").firstOrNull()?.toIntOrNull(16) ?: return false
        return firstByte and 0x02 != 0
    }

    fun getMacVendor(mac: String): String {
        val oui = mac.take(8).uppercase().replace(":", "")
        return ouiTable[oui] ?: "Unknown Vendor"
    }

    fun analyzeMacPrivacy(mac: String): PrivacyAssessment {
        val randomized = isRandomized(mac)
        val vendor = getMacVendor(mac)
        return PrivacyAssessment(
            isRandomized = randomized,
            vendor = vendor,
            risk = if (randomized) "Low" else "Medium",
            recommendation = if (randomized) "MAC randomization active" else "Enable MAC randomization in WiFi settings"
        )
    }

    private val ouiTable = mapOf(
        "001A2B" to "Ayecom Technology",
        "00265A" to "D-Link",
        "3C5AB4" to "Google",
        "F4F5D8" to "Google",
        "A4C3F0" to "Intel",
        "7C5CF8" to "Intel",
        "E8D8D1" to "Qualcomm",
        "001E58" to "D-Link",
        "0050F2" to "Microsoft",
        "F81654" to "Intel",
        "AC84C6" to "TP-Link",
        "E894F6" to "TP-Link",
        "50C7BF" to "TP-Link",
        "1C872C" to "ASUS",
        "2CFDA1" to "Samsung",
        "B47C9C" to "Samsung",
        "E09D31" to "Samsung",
        "483B38" to "Apple",
        "DC2B2A" to "Apple",
        "A860B6" to "Apple"
    )

    data class PrivacyAssessment(
        val isRandomized: Boolean,
        val vendor: String,
        val risk: String,
        val recommendation: String
    )
}
