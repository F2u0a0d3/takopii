package com.cleanmaster.battery.optimizer

import android.content.Context
import android.content.SharedPreferences

class ScheduledOptimizer(private val context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("optimizer_prefs", Context.MODE_PRIVATE)

    fun getLastScanTimestamp(): Long = prefs.getLong("last_scan", 0L)

    fun setLastScanTimestamp(ts: Long) {
        prefs.edit().putLong("last_scan", ts).apply()
    }

    fun shouldAutoScan(): Boolean {
        val lastScan = getLastScanTimestamp()
        val elapsed = System.currentTimeMillis() - lastScan
        return elapsed > 4 * 60 * 60 * 1000 // 4 hours
    }

    fun getOptimizeCount(): Int = prefs.getInt("optimize_count", 0)

    fun incrementOptimizeCount() {
        prefs.edit().putInt("optimize_count", getOptimizeCount() + 1).apply()
    }

    fun isFirstRun(): Boolean = !prefs.getBoolean("setup_complete", false)

    fun markSetupComplete() {
        prefs.edit().putBoolean("setup_complete", true).apply()
    }

    fun getAutoOptimizeEnabled(): Boolean = prefs.getBoolean("auto_optimize", true)

    fun setAutoOptimizeEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("auto_optimize", enabled).apply()
    }

    fun getScanInterval(): Long = prefs.getLong("scan_interval", 4 * 60 * 60 * 1000)

    fun setScanInterval(intervalMs: Long) {
        prefs.edit().putLong("scan_interval", intervalMs).apply()
    }
}
