package com.wifianalyzer.pro.scanner.util

import kotlin.math.log10
import kotlin.math.pow

object SignalConverter {

    fun dbmToMilliwatts(dbm: Int): Double = 10.0.pow(dbm / 10.0)

    fun milliwattsToDbm(mw: Double): Int = (10 * log10(mw)).toInt()

    fun dbmToPercent(dbm: Int): Int = when {
        dbm >= -50 -> 100
        dbm <= -100 -> 0
        else -> 2 * (dbm + 100)
    }

    fun percentToDbm(percent: Int): Int = when {
        percent >= 100 -> -50
        percent <= 0 -> -100
        else -> percent / 2 - 100
    }

    fun dbmToSignalBars(dbm: Int, maxBars: Int = 5): Int {
        val percent = dbmToPercent(dbm)
        return (percent * maxBars / 100).coerceIn(0, maxBars)
    }

    fun estimateDistance(dbm: Int, frequencyMhz: Int): Double {
        val fspl = 27.55
        val exp = (fspl - (20 * log10(frequencyMhz.toDouble())) + kotlin.math.abs(dbm)) / 20.0
        return 10.0.pow(exp)
    }

    fun qualityLabel(dbm: Int): String = when {
        dbm >= -30 -> "Amazing"
        dbm >= -50 -> "Excellent"
        dbm >= -60 -> "Good"
        dbm >= -67 -> "Reliable"
        dbm >= -70 -> "Fair"
        dbm >= -80 -> "Weak"
        dbm >= -90 -> "Very Weak"
        else -> "Unusable"
    }

    fun colorForSignal(dbm: Int): Int = when {
        dbm >= -60 -> 0xFF4CAF50.toInt()
        dbm >= -70 -> 0xFF8BC34A.toInt()
        dbm >= -80 -> 0xFFFF9800.toInt()
        dbm >= -90 -> 0xFFFF5722.toInt()
        else -> 0xFFF44336.toInt()
    }

    fun snrEstimate(signalDbm: Int, noiseFloorDbm: Int = -90): Int {
        return (signalDbm - noiseFloorDbm).coerceAtLeast(0)
    }

    fun linkSpeedEstimate(snr: Int, channelWidthMhz: Int = 20): Int {
        val efficiency = when {
            snr >= 25 -> 0.85
            snr >= 18 -> 0.65
            snr >= 12 -> 0.45
            snr >= 6 -> 0.25
            else -> 0.1
        }
        val maxRate = FrequencyHelper.estimateMaxThroughput(channelWidthMhz)
        return (maxRate * efficiency).toInt()
    }
}
