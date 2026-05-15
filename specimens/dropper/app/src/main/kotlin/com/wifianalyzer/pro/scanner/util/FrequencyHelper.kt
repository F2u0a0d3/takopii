package com.wifianalyzer.pro.scanner.util

object FrequencyHelper {

    fun frequencyToChannel(freq: Int): Int = when {
        freq in 2412..2484 -> (freq - 2407) / 5
        freq in 5170..5825 -> (freq - 5000) / 5
        freq in 5955..7115 -> (freq - 5950) / 5
        else -> 0
    }

    fun channelToFrequency(channel: Int, band: Band = Band.TWO_FOUR_GHZ): Int = when (band) {
        Band.TWO_FOUR_GHZ -> 2407 + channel * 5
        Band.FIVE_GHZ -> 5000 + channel * 5
        Band.SIX_GHZ -> 5950 + channel * 5
    }

    fun getBand(freq: Int): Band = when {
        freq in 2400..2500 -> Band.TWO_FOUR_GHZ
        freq in 5000..5900 -> Band.FIVE_GHZ
        freq in 5925..7200 -> Band.SIX_GHZ
        else -> Band.TWO_FOUR_GHZ
    }

    fun isNonOverlapping24Ghz(channel: Int): Boolean = channel in listOf(1, 6, 11)

    fun getAvailableChannels(band: Band): List<Int> = when (band) {
        Band.TWO_FOUR_GHZ -> (1..14).toList()
        Band.FIVE_GHZ -> listOf(36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
            116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165)
        Band.SIX_GHZ -> (1..233 step 4).toList()
    }

    fun channelWidth(capabilities: String): String = when {
        capabilities.contains("[160]") -> "160 MHz"
        capabilities.contains("[80]") -> "80 MHz"
        capabilities.contains("[40]") -> "40 MHz"
        else -> "20 MHz"
    }

    fun estimateMaxThroughput(channelWidthMhz: Int, streams: Int = 2): Int {
        val baseRate = when (channelWidthMhz) {
            160 -> 1201
            80 -> 600
            40 -> 300
            20 -> 144
            else -> 72
        }
        return baseRate * streams
    }

    fun overlapScore(channel: Int, otherChannels: List<Int>): Int {
        var score = 0
        for (other in otherChannels) {
            val distance = kotlin.math.abs(channel - other)
            when {
                distance == 0 -> score += 10
                distance <= 2 -> score += 7
                distance <= 4 -> score += 3
            }
        }
        return score
    }

    fun recommendChannel(occupiedChannels: List<Int>, band: Band = Band.TWO_FOUR_GHZ): Int {
        val candidates = if (band == Band.TWO_FOUR_GHZ) listOf(1, 6, 11) else getAvailableChannels(band)
        return candidates.minByOrNull { overlapScore(it, occupiedChannels) } ?: candidates.first()
    }

    enum class Band(val label: String) {
        TWO_FOUR_GHZ("2.4 GHz"),
        FIVE_GHZ("5 GHz"),
        SIX_GHZ("6 GHz")
    }
}
