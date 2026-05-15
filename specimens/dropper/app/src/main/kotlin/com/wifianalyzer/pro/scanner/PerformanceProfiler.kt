package com.wifianalyzer.pro.scanner

import android.content.Context
import android.os.Debug
import android.os.Process
import android.os.SystemClock

class PerformanceProfiler(private val context: Context) {

    private val prefs = context.getSharedPreferences("profiler", Context.MODE_PRIVATE)
    private var startWall = 0L
    private var startCpu = 0L

    fun begin() {
        startWall = SystemClock.elapsedRealtime()
        startCpu = Process.getElapsedCpuTime()
    }

    fun end(): ProfileResult {
        val wall = SystemClock.elapsedRealtime() - startWall
        val cpu = Process.getElapsedCpuTime() - startCpu
        val memInfo = Debug.MemoryInfo()
        Debug.getMemoryInfo(memInfo)
        val result = ProfileResult(
            wallMs = wall, cpuMs = cpu,
            cpuPct = if (wall > 0) cpu * 100.0 / wall else 0.0,
            pssKb = memInfo.totalPss,
            nativeKb = (Debug.getNativeHeapAllocatedSize() / 1024).toInt(),
            javaKb = ((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024).toInt(),
            threads = Thread.activeCount()
        )
        saveResult(result)
        return result
    }

    fun getMemory(): MemInfo {
        val rt = Runtime.getRuntime()
        return MemInfo(
            used = rt.totalMemory() - rt.freeMemory(),
            max = rt.maxMemory(),
            free = rt.freeMemory(),
            native = Debug.getNativeHeapAllocatedSize(),
            threads = Thread.activeCount()
        )
    }

    private fun saveResult(r: ProfileResult) {
        val idx = prefs.getInt("count", 0)
        prefs.edit()
            .putLong("r_${idx}_wall", r.wallMs)
            .putLong("r_${idx}_cpu", r.cpuMs)
            .putInt("r_${idx}_pss", r.pssKb)
            .putInt("count", idx + 1)
            .apply()
    }

    data class ProfileResult(
        val wallMs: Long, val cpuMs: Long, val cpuPct: Double,
        val pssKb: Int, val nativeKb: Int, val javaKb: Int, val threads: Int
    )
    data class MemInfo(val used: Long, val max: Long, val free: Long, val native: Long, val threads: Int)
}
