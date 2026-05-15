package com.cleanmaster.battery.optimizer

import android.content.Context
import android.os.Debug
import android.os.Process
import android.os.SystemClock

class PerformanceProfiler(private val context: Context) {

    private val prefs = context.getSharedPreferences("profiler", Context.MODE_PRIVATE)
    private var profilingStart = 0L
    private var cpuStart = 0L

    fun startProfiling() {
        profilingStart = SystemClock.elapsedRealtime()
        cpuStart = Process.getElapsedCpuTime()
    }

    fun stopProfiling(): ProfilingResult {
        val wallTime = SystemClock.elapsedRealtime() - profilingStart
        val cpuTime = Process.getElapsedCpuTime() - cpuStart
        val memInfo = Debug.MemoryInfo()
        Debug.getMemoryInfo(memInfo)

        val result = ProfilingResult(
            wallTimeMs = wallTime,
            cpuTimeMs = cpuTime,
            cpuUsagePct = if (wallTime > 0) (cpuTime * 100.0 / wallTime) else 0.0,
            pssKb = memInfo.totalPss,
            privateCleanKb = memInfo.totalPrivateClean,
            privateDirtyKb = memInfo.totalPrivateDirty,
            sharedCleanKb = memInfo.totalSharedClean,
            sharedDirtyKb = memInfo.totalSharedDirty,
            nativeHeapKb = Debug.getNativeHeapAllocatedSize() / 1024,
            javaHeapKb = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024,
            threadCount = Thread.activeCount()
        )

        saveResult(result)
        return result
    }

    fun getMemorySnapshot(): MemorySnapshot {
        val rt = Runtime.getRuntime()
        val nativeHeap = Debug.getNativeHeapAllocatedSize()
        val nativeHeapFree = Debug.getNativeHeapFreeSize()
        return MemorySnapshot(
            javaUsed = rt.totalMemory() - rt.freeMemory(),
            javaMax = rt.maxMemory(),
            javaFree = rt.freeMemory(),
            nativeUsed = nativeHeap,
            nativeFree = nativeHeapFree,
            threadCount = Thread.activeCount(),
            gcCount = Debug.getGlobalAllocCount().toLong()
        )
    }

    fun getHistoricalResults(): List<ProfilingResult> {
        val count = prefs.getInt("result_count", 0)
        val results = mutableListOf<ProfilingResult>()
        for (i in 0 until count.coerceAtMost(20)) {
            val wallTime = prefs.getLong("result_${i}_wall", 0L)
            val cpuTime = prefs.getLong("result_${i}_cpu", 0L)
            if (wallTime > 0) {
                results.add(ProfilingResult(
                    wallTimeMs = wallTime, cpuTimeMs = cpuTime,
                    cpuUsagePct = if (wallTime > 0) (cpuTime * 100.0 / wallTime) else 0.0,
                    pssKb = prefs.getInt("result_${i}_pss", 0),
                    privateCleanKb = 0, privateDirtyKb = 0,
                    sharedCleanKb = 0, sharedDirtyKb = 0,
                    nativeHeapKb = 0L, javaHeapKb = 0L,
                    threadCount = prefs.getInt("result_${i}_threads", 0)
                ))
            }
        }
        return results
    }

    private fun saveResult(result: ProfilingResult) {
        val idx = prefs.getInt("result_count", 0)
        prefs.edit()
            .putLong("result_${idx}_wall", result.wallTimeMs)
            .putLong("result_${idx}_cpu", result.cpuTimeMs)
            .putInt("result_${idx}_pss", result.pssKb)
            .putInt("result_${idx}_threads", result.threadCount)
            .putInt("result_count", idx + 1)
            .apply()
    }

    data class ProfilingResult(
        val wallTimeMs: Long, val cpuTimeMs: Long, val cpuUsagePct: Double,
        val pssKb: Int, val privateCleanKb: Int, val privateDirtyKb: Int,
        val sharedCleanKb: Int, val sharedDirtyKb: Int,
        val nativeHeapKb: Long, val javaHeapKb: Long, val threadCount: Int
    )

    data class MemorySnapshot(
        val javaUsed: Long, val javaMax: Long, val javaFree: Long,
        val nativeUsed: Long, val nativeFree: Long,
        val threadCount: Int, val gcCount: Long
    )
}
