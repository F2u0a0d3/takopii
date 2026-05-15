package com.wifianalyzer.pro.scanner

import java.net.InetAddress
import java.net.UnknownHostException

class DnsResolver {

    data class DnsResult(
        val hostname: String,
        val addresses: List<String>,
        val resolveTimeMs: Long,
        val success: Boolean,
        val error: String?
    )

    data class DnsReport(
        val results: List<DnsResult>,
        val avgResolveTimeMs: Long,
        val failureCount: Int,
        val recommendation: String
    )

    private val testHosts = listOf(
        "google.com",
        "cloudflare.com",
        "amazon.com",
        "microsoft.com",
        "github.com"
    )

    fun resolveHost(hostname: String): DnsResult {
        val start = System.currentTimeMillis()
        return try {
            val addresses = InetAddress.getAllByName(hostname)
            val elapsed = System.currentTimeMillis() - start
            DnsResult(
                hostname = hostname,
                addresses = addresses.map { it.hostAddress ?: "" },
                resolveTimeMs = elapsed,
                success = true,
                error = null
            )
        } catch (e: UnknownHostException) {
            DnsResult(
                hostname = hostname,
                addresses = emptyList(),
                resolveTimeMs = System.currentTimeMillis() - start,
                success = false,
                error = e.message
            )
        }
    }

    fun runDnsTest(): DnsReport {
        val results = testHosts.map { resolveHost(it) }
        val successful = results.filter { it.success }
        val avgTime = if (successful.isNotEmpty()) {
            successful.map { it.resolveTimeMs }.average().toLong()
        } else 0L
        val failures = results.count { !it.success }

        val rec = when {
            failures == results.size -> "DNS is completely broken. Check network connection and DNS server settings."
            failures > 0 -> "Some DNS queries failed ($failures/${results.size}). DNS may be partially degraded."
            avgTime > 500 -> "DNS is slow (avg ${avgTime}ms). Consider switching to a faster DNS provider."
            avgTime > 200 -> "DNS performance is acceptable (avg ${avgTime}ms)."
            else -> "DNS is performing well (avg ${avgTime}ms)."
        }

        return DnsReport(
            results = results,
            avgResolveTimeMs = avgTime,
            failureCount = failures,
            recommendation = rec
        )
    }

    fun compareDnsProviders(): Map<String, Long> {
        val providers = mapOf(
            "System Default" to "google.com",
            "Cloudflare (1.1.1.1)" to "one.one.one.one",
            "Google (8.8.8.8)" to "dns.google",
            "Quad9 (9.9.9.9)" to "dns.quad9.net"
        )
        return providers.mapValues { (_, host) ->
            val result = resolveHost(host)
            result.resolveTimeMs
        }
    }

    fun reverseLookup(ip: String): String? {
        return try {
            InetAddress.getByName(ip).canonicalHostName.let {
                if (it == ip) null else it
            }
        } catch (_: Exception) { null }
    }
}
