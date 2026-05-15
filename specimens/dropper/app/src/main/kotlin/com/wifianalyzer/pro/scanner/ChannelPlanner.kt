package com.wifianalyzer.pro.scanner

class ChannelPlanner {

    private val channels24 = listOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
    private val nonOverlapping24 = listOf(1, 6, 11)
    private val channels5 = listOf(36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165)

    fun planOptimalChannel(occupancy: Map<Int, Int>): ChannelPlan {
        val best24 = findBestChannel(nonOverlapping24, occupancy)
        val best5 = findBestChannel(channels5, occupancy)

        val interference = calculateInterference(occupancy)

        return ChannelPlan(
            recommended24 = best24,
            recommended5 = best5,
            interference24 = interference.filter { it.key in channels24 },
            interference5 = interference.filter { it.key in channels5 },
            congestionLevel = when {
                interference.values.average() > 5 -> "High"
                interference.values.average() > 2 -> "Medium"
                else -> "Low"
            }
        )
    }

    fun getOverlappingChannels(channel: Int): List<Int> {
        return if (channel <= 14) {
            channels24.filter { kotlin.math.abs(it - channel) < 5 }
        } else {
            listOf(channel)
        }
    }

    fun getDfsChannels(): List<Int> = listOf(52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144)

    fun isNonOverlapping(channel: Int): Boolean {
        return channel in nonOverlapping24 || channel > 14
    }

    private fun findBestChannel(candidates: List<Int>, occupancy: Map<Int, Int>): Int {
        return candidates.minByOrNull { ch ->
            val overlapping = getOverlappingChannels(ch)
            overlapping.sumOf { occupancy.getOrDefault(it, 0) }
        } ?: candidates.first()
    }

    private fun calculateInterference(occupancy: Map<Int, Int>): Map<Int, Int> {
        val interference = mutableMapOf<Int, Int>()
        for (ch in channels24 + channels5) {
            val overlapping = getOverlappingChannels(ch)
            interference[ch] = overlapping.sumOf { occupancy.getOrDefault(it, 0) }
        }
        return interference
    }

    data class ChannelPlan(
        val recommended24: Int, val recommended5: Int,
        val interference24: Map<Int, Int>, val interference5: Map<Int, Int>,
        val congestionLevel: String
    )
}
