package com.wifianalyzer.pro.scanner

class SignalAnalyzer {

    data class SignalReport(
        val current: Int,
        val average: Int,
        val min: Int,
        val max: Int,
        val samples: Int,
        val quality: String,
        val recommendation: String
    )

    private val history = mutableListOf<Int>()

    fun addSample(rssi: Int) {
        history.add(rssi)
        if (history.size > 100) history.removeAt(0)
    }

    fun analyze(): SignalReport {
        if (history.isEmpty()) return SignalReport(0, 0, 0, 0, 0, "N/A", "Start scanning to collect data")
        val avg = history.average().toInt()
        val min = history.min()
        val max = history.max()
        val quality = qualityLabel(avg)
        val rec = recommendation(avg)
        return SignalReport(history.last(), avg, min, max, history.size, quality, rec)
    }

    fun qualityLabel(rssi: Int): String = when {
        rssi >= -30 -> "Excellent"
        rssi >= -50 -> "Very Good"
        rssi >= -60 -> "Good"
        rssi >= -70 -> "Fair"
        rssi >= -80 -> "Weak"
        else -> "Very Weak"
    }

    fun recommendation(rssi: Int): String = when {
        rssi >= -50 -> "Signal is strong. No action needed."
        rssi >= -60 -> "Good signal. Consider moving closer for better speed."
        rssi >= -70 -> "Fair signal. Try repositioning your router."
        rssi >= -80 -> "Weak signal. Move closer to router or add a repeater."
        else -> "Very weak. Consider a WiFi extender or mesh system."
    }

    fun getNoiseFloor(): Int = -95

    fun getSignalToNoise(rssi: Int): Int = rssi - getNoiseFloor()

    fun estimateSpeed(rssi: Int, band: String): Int {
        val base = if (band == "5 GHz") 866 else 144
        val factor = when {
            rssi >= -30 -> 1.0
            rssi >= -50 -> 0.85
            rssi >= -60 -> 0.65
            rssi >= -70 -> 0.45
            rssi >= -80 -> 0.25
            else -> 0.1
        }
        return (base * factor).toInt()
    }

    fun clear() { history.clear() }
}
