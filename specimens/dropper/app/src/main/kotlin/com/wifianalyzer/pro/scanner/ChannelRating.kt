package com.wifianalyzer.pro.scanner

data class ChannelScore(
    val channel: Int,
    val frequency: Int,
    val band: String,
    val networksOnChannel: Int,
    val averageSignal: Int,
    val interference: String,
    val rating: Int
)

class ChannelRating {

    fun analyzeChannels(networks: List<WifiNetwork>): List<ChannelScore> {
        val byChannel = networks.groupBy { it.channel }
        val allChannels24 = listOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
        val allChannels5 = listOf(36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165)

        val scores = mutableListOf<ChannelScore>()
        for (ch in allChannels24) {
            val netsOnCh = byChannel[ch] ?: emptyList()
            val avgSig = if (netsOnCh.isNotEmpty()) netsOnCh.map { it.level }.average().toInt() else 0
            scores.add(buildScore(ch, channelToFreq24(ch), "2.4 GHz", netsOnCh.size, avgSig, networks))
        }
        for (ch in allChannels5) {
            val netsOnCh = byChannel[ch] ?: emptyList()
            val avgSig = if (netsOnCh.isNotEmpty()) netsOnCh.map { it.level }.average().toInt() else 0
            scores.add(buildScore(ch, channelToFreq5(ch), "5 GHz", netsOnCh.size, avgSig, networks))
        }
        return scores.sortedByDescending { it.rating }
    }

    private fun buildScore(ch: Int, freq: Int, band: String, count: Int, avgSig: Int, allNets: List<WifiNetwork>): ChannelScore {
        val overlap = countOverlapping(ch, band, allNets)
        val interference = when {
            overlap == 0 -> "None"
            overlap <= 2 -> "Low"
            overlap <= 5 -> "Medium"
            else -> "High"
        }
        val rating = calculateRating(count, overlap, avgSig)
        return ChannelScore(ch, freq, band, count, avgSig, interference, rating)
    }

    private fun countOverlapping(ch: Int, band: String, nets: List<WifiNetwork>): Int {
        if (band == "5 GHz") return nets.count { it.channel == ch }
        return nets.count { kotlin.math.abs(it.channel - ch) <= 2 && it.band == "2.4 GHz" }
    }

    private fun calculateRating(count: Int, overlap: Int, avgSig: Int): Int {
        var r = 100
        r -= count * 10
        r -= overlap * 5
        if (avgSig < -70) r += 10
        return r.coerceIn(0, 100)
    }

    fun getBestChannel24(networks: List<WifiNetwork>): Int {
        val scores = analyzeChannels(networks).filter { it.band == "2.4 GHz" }
        return scores.maxByOrNull { it.rating }?.channel ?: 1
    }

    fun getBestChannel5(networks: List<WifiNetwork>): Int {
        val scores = analyzeChannels(networks).filter { it.band == "5 GHz" }
        return scores.maxByOrNull { it.rating }?.channel ?: 36
    }

    private fun channelToFreq24(ch: Int): Int = 2412 + (ch - 1) * 5
    private fun channelToFreq5(ch: Int): Int = 5000 + ch * 5
}
