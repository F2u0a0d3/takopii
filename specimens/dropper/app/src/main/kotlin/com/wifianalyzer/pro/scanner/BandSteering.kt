package com.wifianalyzer.pro.scanner

class BandSteering {

    fun shouldSteer(rssi24: Int, rssi5: Int, noise24: Int = -90, noise5: Int = -90): SteerResult {
        val snr24 = rssi24 - noise24
        val snr5 = rssi5 - noise5
        val prefer5 = rssi5 > -70 && snr5 > snr24 - 5
        val prefer24 = rssi24 - rssi5 > 15
        return when {
            prefer5 -> SteerResult("5GHz", "Better SNR on 5GHz band", snr5 - snr24)
            prefer24 -> SteerResult("2.4GHz", "Significantly stronger on 2.4GHz", rssi24 - rssi5)
            else -> SteerResult("Current", "No band change recommended", 0)
        }
    }

    fun analyzeChannelWidth(frequency: Int): List<ChannelWidth> {
        val widths = mutableListOf<ChannelWidth>()
        widths.add(ChannelWidth(20, true, "Standard"))
        if (frequency > 4900) {
            widths.add(ChannelWidth(40, true, "Bonded"))
            widths.add(ChannelWidth(80, frequency in 5170..5835, "VHT"))
            widths.add(ChannelWidth(160, frequency in 5170..5330 || frequency in 5490..5730, "VHT160"))
        } else {
            widths.add(ChannelWidth(40, true, "Bonded (limited in 2.4GHz)"))
        }
        return widths
    }

    fun estimateThroughput(channelWidth: Int, streams: Int, modulation: String = "256-QAM"): Double {
        val baseRate = when (channelWidth) {
            20 -> 86.7
            40 -> 200.0
            80 -> 433.3
            160 -> 866.7
            else -> 54.0
        }
        val modFactor = when (modulation) {
            "1024-QAM" -> 1.25
            "256-QAM" -> 1.0
            "64-QAM" -> 0.75
            "16-QAM" -> 0.5
            else -> 0.35
        }
        return baseRate * streams * modFactor
    }

    fun getRoamingRecommendation(currentRssi: Int, targetRssi: Int, hysteresis: Int = 5): String {
        return when {
            targetRssi - currentRssi > hysteresis -> "Roam recommended (${targetRssi - currentRssi}dB improvement)"
            currentRssi < -75 && targetRssi > currentRssi -> "Consider roaming (weak signal)"
            else -> "Stay on current AP"
        }
    }

    data class SteerResult(val band: String, val reason: String, val delta: Int)
    data class ChannelWidth(val mhz: Int, val available: Boolean, val label: String)
}
