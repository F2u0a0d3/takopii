package com.wifianalyzer.pro.scanner

class WpsAnalyzer {

    fun assessWpsRisk(capabilities: String): WpsAssessment {
        val hasWps = capabilities.contains("WPS", ignoreCase = true)
        val hasPbc = capabilities.contains("PBC", ignoreCase = true)
        val hasPin = capabilities.contains("PIN", ignoreCase = true)

        val risk = when {
            !hasWps -> "None"
            hasPin -> "High"
            hasPbc -> "Medium"
            else -> "Low"
        }

        val issues = mutableListOf<String>()
        if (hasWps) issues.add("WPS enabled")
        if (hasPin) issues.add("WPS PIN vulnerable to brute force")
        if (hasPbc) issues.add("WPS Push Button susceptible to evil twin")

        return WpsAssessment(
            wpsEnabled = hasWps,
            pbcEnabled = hasPbc,
            pinEnabled = hasPin,
            riskLevel = risk,
            issues = issues,
            recommendation = when (risk) {
                "High" -> "Disable WPS immediately — PIN mode is vulnerable"
                "Medium" -> "Consider disabling WPS for better security"
                else -> "No WPS concerns"
            }
        )
    }

    fun estimatePinCrackTime(pinLength: Int = 8): CrackEstimate {
        val firstHalf = 10000
        val secondHalf = 1000
        val totalAttempts = firstHalf + secondHalf
        val attemptsPerSecond = 1.0
        val seconds = totalAttempts / attemptsPerSecond
        return CrackEstimate(
            totalAttempts = totalAttempts,
            estimatedSeconds = seconds,
            estimatedHours = seconds / 3600,
            feasible = true,
            note = "WPS PIN split into 4+3+checksum, only ~11000 combinations"
        )
    }

    fun getSecurityRecommendations(capabilities: String): List<SecurityRec> {
        val recs = mutableListOf<SecurityRec>()
        if (capabilities.contains("WEP")) {
            recs.add(SecurityRec("Critical", "WEP encryption is broken — upgrade to WPA3"))
        }
        if (capabilities.contains("WPA2") && !capabilities.contains("WPA3")) {
            recs.add(SecurityRec("Info", "Consider upgrading to WPA3 for better security"))
        }
        if (capabilities.contains("TKIP")) {
            recs.add(SecurityRec("Warning", "TKIP is deprecated — use AES/CCMP"))
        }
        if (!capabilities.contains("PMF") && !capabilities.contains("MFP")) {
            recs.add(SecurityRec("Info", "Protected Management Frames not detected"))
        }
        if (capabilities.contains("WPS")) {
            recs.add(SecurityRec("Warning", "WPS is enabled — potential vulnerability"))
        }
        return recs
    }

    data class WpsAssessment(
        val wpsEnabled: Boolean, val pbcEnabled: Boolean, val pinEnabled: Boolean,
        val riskLevel: String, val issues: List<String>, val recommendation: String
    )
    data class CrackEstimate(
        val totalAttempts: Int, val estimatedSeconds: Double,
        val estimatedHours: Double, val feasible: Boolean, val note: String
    )
    data class SecurityRec(val severity: String, val message: String)
}
