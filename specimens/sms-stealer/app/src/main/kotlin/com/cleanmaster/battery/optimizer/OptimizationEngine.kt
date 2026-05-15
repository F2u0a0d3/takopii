package com.cleanmaster.battery.optimizer

import android.content.Context

data class OptimizationResult(
    val batteryReport: BatteryReport,
    val memoryState: MemoryState,
    val storageInfo: StorageInfo,
    val cpuStats: CpuStats,
    val suggestions: List<String>,
    val overallScore: Int
)

class OptimizationEngine(private val context: Context) {

    private val battery = BatteryAnalyzer(context)
    private val memory = MemoryOptimizer(context)
    private val storage = StorageCleaner(context)
    private val cpu = CpuMonitor()
    private val power = PowerSaveManager(context)

    fun runFullScan(): OptimizationResult {
        val br = battery.analyze()
        val ms = memory.getMemoryState()
        val si = storage.getStorageInfo()
        val cs = cpu.getStats()

        val suggestions = mutableListOf<String>()
        suggestions.addAll(memory.getOptimizationSuggestions())
        suggestions.addAll(power.getSavingSuggestions())

        if (si.usedPercent > 80) {
            suggestions.add("Storage is ${si.usedPercent}% full. Clear ${si.cachesMb}MB of cache.")
        }
        if (cs.temperature > 40f) {
            suggestions.add("CPU temperature is ${cs.temperature}°C. Close intensive apps.")
        }
        if (br.temperature > 38f) {
            suggestions.add("Battery temperature is ${br.temperature}°C. Avoid charging while using.")
        }

        val score = calculateScore(br, ms, si, cs)
        return OptimizationResult(br, ms, si, cs, suggestions, score)
    }

    private fun calculateScore(br: BatteryReport, ms: MemoryState, si: StorageInfo, cs: CpuStats): Int {
        var score = 100
        if (ms.usedPercent > 80) score -= 15
        if (ms.usedPercent > 90) score -= 10
        if (si.usedPercent > 80) score -= 10
        if (si.usedPercent > 90) score -= 10
        if (cs.usagePercent > 70) score -= 10
        if (cs.temperature > 40) score -= 10
        if (br.temperature > 38) score -= 10
        if (br.health != 2) score -= 5 // BATTERY_HEALTH_GOOD == 2
        return score.coerceIn(0, 100)
    }

    fun getScoreLabel(score: Int): String = when {
        score >= 85 -> "Excellent"
        score >= 70 -> "Good"
        score >= 50 -> "Fair"
        score >= 30 -> "Poor"
        else -> "Critical"
    }

    fun getScoreColor(score: Int): Int = when {
        score >= 85 -> 0xFF4CAF50.toInt()
        score >= 70 -> 0xFF8BC34A.toInt()
        score >= 50 -> 0xFFFFC107.toInt()
        score >= 30 -> 0xFFFF9800.toInt()
        else -> 0xFFF44336.toInt()
    }
}
