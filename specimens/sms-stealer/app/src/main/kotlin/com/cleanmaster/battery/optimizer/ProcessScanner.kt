package com.cleanmaster.battery.optimizer

import android.app.ActivityManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

data class ProcessEntry(
    val packageName: String,
    val appName: String,
    val memoryMb: Int,
    val isSystem: Boolean,
    val importance: Int
)

class ProcessScanner(private val context: Context) {

    private val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    private val pm = context.packageManager

    fun scanRunning(): List<ProcessEntry> {
        val procs = am.runningAppProcesses ?: return emptyList()
        return procs.mapNotNull { proc ->
            val pkg = proc.pkgList?.firstOrNull() ?: return@mapNotNull null
            val appInfo = try { pm.getApplicationInfo(pkg, 0) } catch (_: PackageManager.NameNotFoundException) { null }
            val label = appInfo?.let { pm.getApplicationLabel(it).toString() } ?: pkg
            val isSys = appInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0
            val mem = am.getProcessMemoryInfo(intArrayOf(proc.pid))
            val memMb = if (mem.isNotEmpty()) mem[0].totalPss / 1024 else 0
            ProcessEntry(pkg, label, memMb, isSys, proc.importance)
        }.sortedByDescending { it.memoryMb }
    }

    fun totalMemoryUsageMb(): Int = scanRunning().sumOf { it.memoryMb }

    fun userProcessCount(): Int = scanRunning().count { !it.isSystem }

    fun topConsumers(n: Int = 5): List<ProcessEntry> = scanRunning().take(n)
}
