package com.wifianalyzer.pro.scanner

import android.content.Context
import android.content.SharedPreferences

class ScanScheduler(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("scan_prefs", Context.MODE_PRIVATE)

    fun getAutoScanEnabled(): Boolean = prefs.getBoolean("auto_scan", true)

    fun setAutoScanEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("auto_scan", enabled).apply()
    }

    fun getScanIntervalMs(): Long = prefs.getLong("scan_interval", 30_000)

    fun setScanIntervalMs(interval: Long) {
        prefs.edit().putLong("scan_interval", interval).apply()
    }

    fun getLastScanTime(): Long = prefs.getLong("last_scan", 0)

    fun setLastScanTime(time: Long) {
        prefs.edit().putLong("last_scan", time).apply()
    }

    fun shouldScanNow(): Boolean {
        if (!getAutoScanEnabled()) return false
        return System.currentTimeMillis() - getLastScanTime() >= getScanIntervalMs()
    }

    fun isFirstLaunch(): Boolean = !prefs.getBoolean("launched_before", false)

    fun markLaunched() {
        prefs.edit().putBoolean("launched_before", true).apply()
    }

    fun getNotifyOnNewNetworks(): Boolean = prefs.getBoolean("notify_new", false)

    fun setNotifyOnNewNetworks(enabled: Boolean) {
        prefs.edit().putBoolean("notify_new", enabled).apply()
    }

    fun getShowHiddenNetworks(): Boolean = prefs.getBoolean("show_hidden", true)

    fun setShowHiddenNetworks(show: Boolean) {
        prefs.edit().putBoolean("show_hidden", show).apply()
    }
}
