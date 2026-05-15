package com.cleanmaster.battery.optimizer

import android.app.ActivityManager
import android.content.Context

data class MemoryState(
    val totalRamMb: Long,
    val availableRamMb: Long,
    val usedRamMb: Long,
    val usedPercent: Int,
    val lowMemory: Boolean,
    val threshold: Long
)

class MemoryOptimizer(private val context: Context) {

    private val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager

    fun getMemoryState(): MemoryState {
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        val totalMb = info.totalMem / (1024 * 1024)
        val availMb = info.availMem / (1024 * 1024)
        val usedMb = totalMb - availMb
        val pct = if (totalMb > 0) ((usedMb * 100) / totalMb).toInt() else 0
        return MemoryState(
            totalRamMb = totalMb,
            availableRamMb = availMb,
            usedRamMb = usedMb,
            usedPercent = pct,
            lowMemory = info.lowMemory,
            threshold = info.threshold / (1024 * 1024)
        )
    }

    fun getOptimizationSuggestions(): List<String> {
        val state = getMemoryState()
        val suggestions = mutableListOf<String>()
        if (state.usedPercent > 85) {
            suggestions.add("RAM usage is high (${state.usedPercent}%). Close unused apps.")
        }
        if (state.lowMemory) {
            suggestions.add("Device is in low-memory state. Restart recommended.")
        }
        if (state.availableRamMb < 512) {
            suggestions.add("Less than 512 MB available. Performance may be impacted.")
        }
        if (suggestions.isEmpty()) {
            suggestions.add("Memory usage is healthy (${state.usedPercent}%).")
        }
        return suggestions
    }

    fun getMaxHeapMb(): Int = (Runtime.getRuntime().maxMemory() / (1024 * 1024)).toInt()

    fun getCurrentHeapMb(): Int = ((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024)).toInt()
}
