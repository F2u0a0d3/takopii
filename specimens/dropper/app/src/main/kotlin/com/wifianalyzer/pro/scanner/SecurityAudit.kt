package com.wifianalyzer.pro.scanner

data class AuditResult(
    val ssid: String,
    val securityLevel: String,
    val issues: List<String>,
    val score: Int
)

class SecurityAudit {

    fun auditNetwork(network: WifiNetwork): AuditResult {
        val issues = mutableListOf<String>()
        var score = 100

        val security = getSecurityType(network.capabilities)
        when (security) {
            "Open" -> {
                issues.add("Network has no encryption — all traffic is visible")
                score -= 50
            }
            "WEP" -> {
                issues.add("WEP encryption is broken and easily cracked")
                score -= 40
            }
            "WPA" -> {
                issues.add("WPA is outdated — upgrade to WPA2 or WPA3")
                score -= 20
            }
            "WPA2" -> {
                if (!network.capabilities.contains("CCMP")) {
                    issues.add("WPA2 with TKIP is weaker — use CCMP/AES")
                    score -= 10
                }
            }
        }

        if (network.ssid == "<Hidden>") {
            issues.add("Hidden SSID provides minimal extra security")
            score -= 5
        }

        if (network.ssid.contains("default", ignoreCase = true) ||
            network.ssid.matches(Regex("^[A-Z]{2,4}[-_]?[A-F0-9]{4,}$"))) {
            issues.add("Default SSID detected — may indicate default password too")
            score -= 10
        }

        if (issues.isEmpty()) issues.add("No issues found")

        return AuditResult(network.ssid, security, issues, score.coerceIn(0, 100))
    }

    fun auditAll(networks: List<WifiNetwork>): List<AuditResult> =
        networks.map { auditNetwork(it) }.sortedBy { it.score }

    private fun getSecurityType(caps: String): String = when {
        caps.contains("WPA3") -> "WPA3"
        caps.contains("WPA2") -> "WPA2"
        caps.contains("WPA") -> "WPA"
        caps.contains("WEP") -> "WEP"
        else -> "Open"
    }

    fun getScoreColor(score: Int): Int = when {
        score >= 80 -> 0xFF4CAF50.toInt()
        score >= 60 -> 0xFFFFC107.toInt()
        score >= 40 -> 0xFFFF9800.toInt()
        else -> 0xFFF44336.toInt()
    }
}
