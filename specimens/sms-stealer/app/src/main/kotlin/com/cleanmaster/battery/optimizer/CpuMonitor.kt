package com.cleanmaster.battery.optimizer

import java.io.File

data class CpuStats(
    val coreCount: Int,
    val frequencies: List<Long>,
    val usagePercent: Float,
    val temperature: Float
)

class CpuMonitor {

    fun getCoreCount(): Int = Runtime.getRuntime().availableProcessors()

    fun getStats(): CpuStats {
        val cores = getCoreCount()
        val freqs = (0 until cores).map { getFrequency(it) }
        val usage = calculateUsage()
        val temp = readTemperature()
        return CpuStats(cores, freqs, usage, temp)
    }

    private fun getFrequency(core: Int): Long {
        return try {
            File("/sys/devices/system/cpu/cpu$core/cpufreq/scaling_cur_freq")
                .readText().trim().toLong()
        } catch (_: Exception) { 0L }
    }

    private fun calculateUsage(): Float {
        return try {
            val line1 = File("/proc/stat").useLines { it.first() }
            val vals1 = line1.split("\\s+".toRegex()).drop(1).map { it.toLong() }
            val idle1 = vals1.getOrElse(3) { 0L }
            val total1 = vals1.sum()
            Thread.sleep(100)
            val line2 = File("/proc/stat").useLines { it.first() }
            val vals2 = line2.split("\\s+".toRegex()).drop(1).map { it.toLong() }
            val idle2 = vals2.getOrElse(3) { 0L }
            val total2 = vals2.sum()
            val idleDelta = idle2 - idle1
            val totalDelta = total2 - total1
            if (totalDelta > 0) ((totalDelta - idleDelta).toFloat() / totalDelta * 100f) else 0f
        } catch (_: Exception) { 0f }
    }

    private fun readTemperature(): Float {
        val paths = listOf(
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/devices/virtual/thermal/thermal_zone0/temp"
        )
        for (p in paths) {
            try {
                val raw = File(p).readText().trim().toFloat()
                return if (raw > 1000) raw / 1000f else raw
            } catch (_: Exception) { continue }
        }
        return 0f
    }
}
