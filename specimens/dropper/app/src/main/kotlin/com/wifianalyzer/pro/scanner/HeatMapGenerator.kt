package com.wifianalyzer.pro.scanner

import com.wifianalyzer.pro.scanner.data.NetworkRecord

class HeatMapGenerator {

    data class HeatMapCell(
        val channel: Int,
        val band: String,
        val networkCount: Int,
        val avgSignalDbm: Int,
        val maxSignalDbm: Int,
        val congestionLevel: String,
        val color: Int
    )

    data class HeatMap(
        val cells: List<HeatMapCell>,
        val totalNetworks: Int,
        val mostCongestedChannel: Int,
        val leastCongestedChannel: Int,
        val recommendation: String
    )

    fun generate(networks: List<NetworkRecord>): HeatMap {
        val grouped = networks.groupBy { it.channel }
        val cells = grouped.map { (channel, nets) ->
            val avgRssi = nets.map { it.rssi }.average().toInt()
            val maxRssi = nets.maxOf { it.rssi }
            val congestion = when {
                nets.size >= 5 -> "High"
                nets.size >= 3 -> "Medium"
                nets.size >= 1 -> "Low"
                else -> "Empty"
            }
            HeatMapCell(
                channel = channel,
                band = nets.first().band(),
                networkCount = nets.size,
                avgSignalDbm = avgRssi,
                maxSignalDbm = maxRssi,
                congestionLevel = congestion,
                color = congestionColor(nets.size)
            )
        }.sortedBy { it.channel }

        val mostCongested = cells.maxByOrNull { it.networkCount }?.channel ?: 0
        val leastCongested = cells.minByOrNull { it.networkCount }?.channel ?: 0

        val rec = buildRecommendation(cells, networks)

        return HeatMap(
            cells = cells,
            totalNetworks = networks.size,
            mostCongestedChannel = mostCongested,
            leastCongestedChannel = leastCongested,
            recommendation = rec
        )
    }

    fun generate24GhzMap(networks: List<NetworkRecord>): HeatMap {
        val filtered = networks.filter { it.frequency in 2400..2500 }
        return generate(filtered)
    }

    fun generate5GhzMap(networks: List<NetworkRecord>): HeatMap {
        val filtered = networks.filter { it.frequency in 5000..5900 }
        return generate(filtered)
    }

    private fun buildRecommendation(cells: List<HeatMapCell>, networks: List<NetworkRecord>): String {
        val channels24 = cells.filter { it.band == "2.4 GHz" }
        val channels5 = cells.filter { it.band == "5 GHz" }

        return buildString {
            if (channels24.any { it.congestionLevel == "High" }) {
                appendLine("2.4 GHz band is congested. Switch to 5 GHz if your device supports it.")
            }
            if (channels5.isEmpty() && networks.isNotEmpty()) {
                appendLine("No 5 GHz networks detected. Your router may not support dual-band.")
            }
            val nonOverlapping = channels24.filter { it.channel in listOf(1, 6, 11) }
            val best = nonOverlapping.minByOrNull { it.networkCount }
            if (best != null) {
                append("Best 2.4 GHz channel: ${best.channel} (${best.networkCount} networks)")
            }
        }
    }

    private fun congestionColor(count: Int): Int = when {
        count >= 5 -> 0xFFF44336.toInt()
        count >= 3 -> 0xFFFF9800.toInt()
        count >= 1 -> 0xFF4CAF50.toInt()
        else -> 0xFF9E9E9E.toInt()
    }
}
