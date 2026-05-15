package com.cleanmaster.battery.optimizer

import android.app.ActivityManager
import android.content.Context
import android.os.Debug

class GarbageCollectorHelper(private val context: Context) {

    data class HeapReport(
        val totalMemoryMb: Float,
        val freeMemoryMb: Float,
        val usedMemoryMb: Float,
        val maxMemoryMb: Float,
        val utilization: Float,
        val gcCount: Long,
        val recommendation: String
    )

    fun getHeapReport(): HeapReport {
        val runtime = Runtime.getRuntime()
        val total = runtime.totalMemory().toFloat() / (1024 * 1024)
        val free = runtime.freeMemory().toFloat() / (1024 * 1024)
        val used = total - free
        val max = runtime.maxMemory().toFloat() / (1024 * 1024)
        val utilization = used / max

        val gcInfo = Debug.getRuntimeStat("art.gc.gc-count")
        val gcCount = gcInfo?.toLongOrNull() ?: 0

        val rec = when {
            utilization > 0.85f -> "Memory pressure is high. Consider closing unused features or reducing cache sizes."
            utilization > 0.7f -> "Memory usage is elevated. Monitor for potential GC thrashing."
            else -> "Memory usage is healthy. Current heap has plenty of room."
        }

        return HeapReport(
            totalMemoryMb = total,
            freeMemoryMb = free,
            usedMemoryMb = used,
            maxMemoryMb = max,
            utilization = utilization,
            gcCount = gcCount,
            recommendation = rec
        )
    }

    fun getSystemMemoryReport(): SystemMemoryReport {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)

        val totalGb = mi.totalMem.toFloat() / (1024 * 1024 * 1024)
        val availGb = mi.availMem.toFloat() / (1024 * 1024 * 1024)
        val usedGb = totalGb - availGb
        val usedPct = (usedGb / totalGb) * 100f

        return SystemMemoryReport(
            totalGb = totalGb,
            availableGb = availGb,
            usedGb = usedGb,
            usedPercent = usedPct,
            lowMemory = mi.lowMemory,
            threshold = mi.threshold.toFloat() / (1024 * 1024)
        )
    }

    fun getMemoryOptimizationTips(): List<String> {
        val tips = mutableListOf<String>()
        val heap = getHeapReport()
        val sys = getSystemMemoryReport()

        if (heap.utilization > 0.7f) {
            tips.add("App heap usage is ${(heap.utilization * 100).toInt()}% - consider reducing bitmap cache sizes")
        }
        if (sys.lowMemory) {
            tips.add("System is in low memory state - close background apps to free RAM")
        }
        if (sys.usedPercent > 80f) {
            tips.add("System RAM is ${sys.usedPercent.toInt()}% utilized - heavy multitasking may cause slowdowns")
        }

        tips.add("Enable adaptive battery to let the system learn your usage patterns")
        tips.add("Avoid memory-intensive apps when battery is below 20%")

        return tips
    }

    fun suggestGarbageCollection(): Boolean {
        val heap = getHeapReport()
        return heap.utilization > 0.75f
    }

    data class SystemMemoryReport(
        val totalGb: Float,
        val availableGb: Float,
        val usedGb: Float,
        val usedPercent: Float,
        val lowMemory: Boolean,
        val threshold: Float
    )
}
