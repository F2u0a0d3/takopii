package com.wifianalyzer.pro.scanner

import java.net.InetAddress

data class PingResult(
    val host: String,
    val reachable: Boolean,
    val latencyMs: Int,
    val ttl: Int
)

class PingTester {

    fun ping(host: String, timeoutMs: Int = 3000): PingResult {
        val start = System.nanoTime()
        return try {
            val addr = InetAddress.getByName(host)
            val reachable = addr.isReachable(timeoutMs)
            val elapsed = ((System.nanoTime() - start) / 1_000_000).toInt()
            PingResult(host, reachable, elapsed, 64)
        } catch (_: Exception) {
            val elapsed = ((System.nanoTime() - start) / 1_000_000).toInt()
            PingResult(host, false, elapsed, 0)
        }
    }

    fun pingMultiple(hosts: List<String>): List<PingResult> = hosts.map { ping(it) }

    fun traceRoute(host: String, maxHops: Int = 15): List<PingResult> {
        val results = mutableListOf<PingResult>()
        for (ttl in 1..maxHops) {
            val result = ping(host, 2000)
            results.add(result.copy(ttl = ttl))
            if (result.reachable) break
        }
        return results
    }

    fun getDefaultGateways(): List<String> = listOf("192.168.1.1", "192.168.0.1", "10.0.0.1", "10.0.2.2")

    fun calculateJitter(latencies: List<Int>): Int {
        if (latencies.size < 2) return 0
        val diffs = latencies.zipWithNext().map { (a, b) -> kotlin.math.abs(b - a) }
        return diffs.average().toInt()
    }
}
