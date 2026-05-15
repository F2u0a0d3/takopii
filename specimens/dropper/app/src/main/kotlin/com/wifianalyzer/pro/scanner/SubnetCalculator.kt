package com.wifianalyzer.pro.scanner

data class SubnetInfo(
    val ip: String,
    val mask: String,
    val networkAddress: String,
    val broadcastAddress: String,
    val cidr: Int,
    val hostCount: Int,
    val firstHost: String,
    val lastHost: String
)

class SubnetCalculator {

    fun calculate(ip: String, mask: String): SubnetInfo {
        val ipParts = ip.split(".").map { it.toInt() }
        val maskParts = mask.split(".").map { it.toInt() }

        val netParts = ipParts.zip(maskParts).map { (i, m) -> i and m }
        val bcastParts = netParts.zip(maskParts).map { (n, m) -> n or (m xor 0xFF) }

        val cidr = maskParts.sumOf { Integer.bitCount(it) }
        val hostBits = 32 - cidr
        val hostCount = if (hostBits >= 2) (1 shl hostBits) - 2 else 0

        val firstHost = netParts.toMutableList().apply { this[3] = this[3] + 1 }
        val lastHost = bcastParts.toMutableList().apply { this[3] = this[3] - 1 }

        return SubnetInfo(
            ip = ip,
            mask = mask,
            networkAddress = netParts.joinToString("."),
            broadcastAddress = bcastParts.joinToString("."),
            cidr = cidr,
            hostCount = hostCount,
            firstHost = firstHost.joinToString("."),
            lastHost = lastHost.joinToString(".")
        )
    }

    fun commonMasks(): List<Pair<String, Int>> = listOf(
        "255.255.255.0" to 24,
        "255.255.254.0" to 23,
        "255.255.252.0" to 22,
        "255.255.248.0" to 21,
        "255.255.240.0" to 20,
        "255.255.0.0" to 16,
        "255.0.0.0" to 8
    )

    fun isPrivateAddress(ip: String): Boolean {
        val parts = ip.split(".").mapNotNull { it.toIntOrNull() }
        if (parts.size != 4) return false
        return (parts[0] == 10) ||
            (parts[0] == 172 && parts[1] in 16..31) ||
            (parts[0] == 192 && parts[1] == 168)
    }

    fun ipToLong(ip: String): Long {
        val parts = ip.split(".").map { it.toLong() }
        return (parts[0] shl 24) + (parts[1] shl 16) + (parts[2] shl 8) + parts[3]
    }

    fun longToIp(l: Long): String {
        return "${(l shr 24) and 0xFF}.${(l shr 16) and 0xFF}.${(l shr 8) and 0xFF}.${l and 0xFF}"
    }
}
