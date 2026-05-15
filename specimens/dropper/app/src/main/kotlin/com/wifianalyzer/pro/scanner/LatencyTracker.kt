package com.wifianalyzer.pro.scanner

import java.net.InetAddress

class LatencyTracker {

    data class LatencyResult(
        val host: String,
        val latencyMs: Long,
        val reachable: Boolean,
        val hops: Int
    )

    data class LatencyReport(
        val results: List<LatencyResult>,
        val avgLatencyMs: Long,
        val minLatencyMs: Long,
        val maxLatencyMs: Long,
        val packetLoss: Float,
        val jitterMs: Long,
        val qualityRating: String
    )

    private val defaultTargets = listOf(
        "8.8.8.8",
        "1.1.1.1",
        "208.67.222.222",
        "9.9.9.9"
    )

    fun measureLatency(host: String, count: Int = 5, timeoutMs: Int = 3000): LatencyReport {
        val results = (1..count).map { attempt ->
            val start = System.currentTimeMillis()
            val reachable = try {
                InetAddress.getByName(host).isReachable(timeoutMs)
            } catch (_: Exception) { false }
            val elapsed = System.currentTimeMillis() - start
            LatencyResult(host, elapsed, reachable, estimateHops(elapsed))
        }

        val successful = results.filter { it.reachable }
        val latencies = successful.map { it.latencyMs }
        val avg = if (latencies.isNotEmpty()) latencies.average().toLong() else 0
        val min = latencies.minOrNull() ?: 0
        val max = latencies.maxOrNull() ?: 0
        val loss = (count - successful.size).toFloat() / count * 100
        val jitter = if (latencies.size >= 2) {
            latencies.zipWithNext().map { (a, b) -> kotlin.math.abs(a - b) }.average().toLong()
        } else 0

        val rating = when {
            loss > 50 -> "Unusable"
            loss > 10 -> "Poor"
            avg > 200 -> "Poor"
            avg > 100 -> "Fair"
            avg > 50 -> "Good"
            else -> "Excellent"
        }

        return LatencyReport(results, avg, min, max, loss, jitter, rating)
    }

    fun measureAllDefaultTargets(): List<LatencyReport> {
        return defaultTargets.map { measureLatency(it, count = 3) }
    }

    fun findBestDns(): Pair<String, Long> {
        val reports = measureAllDefaultTargets()
        val best = reports.filter { it.packetLoss < 50 }
            .minByOrNull { it.avgLatencyMs }
        return if (best != null) {
            best.results.first().host to best.avgLatencyMs
        } else "none" to -1
    }

    private fun estimateHops(latencyMs: Long): Int = when {
        latencyMs < 5 -> 1
        latencyMs < 15 -> 3
        latencyMs < 50 -> 7
        latencyMs < 100 -> 12
        else -> 18
    }
}
