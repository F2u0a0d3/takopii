package com.wifianalyzer.pro.scanner.data

import android.content.Context
import android.content.SharedPreferences

class PreferencesManager(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("wifi_prefs", Context.MODE_PRIVATE)

    var autoScanOnLaunch: Boolean
        get() = prefs.getBoolean(KEY_AUTO_SCAN, true)
        set(value) = prefs.edit().putBoolean(KEY_AUTO_SCAN, value).apply()

    var include5Ghz: Boolean
        get() = prefs.getBoolean(KEY_5GHZ, true)
        set(value) = prefs.edit().putBoolean(KEY_5GHZ, value).apply()

    var detectHiddenNetworks: Boolean
        get() = prefs.getBoolean(KEY_HIDDEN, false)
        set(value) = prefs.edit().putBoolean(KEY_HIDDEN, value).apply()

    var continuousScanning: Boolean
        get() = prefs.getBoolean(KEY_CONTINUOUS, false)
        set(value) = prefs.edit().putBoolean(KEY_CONTINUOUS, value).apply()

    var scanIntervalSeconds: Int
        get() = prefs.getInt(KEY_INTERVAL, 30)
        set(value) = prefs.edit().putInt(KEY_INTERVAL, value).apply()

    var speedTestOnConnect: Boolean
        get() = prefs.getBoolean(KEY_SPEED_TEST, false)
        set(value) = prefs.edit().putBoolean(KEY_SPEED_TEST, value).apply()

    var pingTestOnConnect: Boolean
        get() = prefs.getBoolean(KEY_PING_TEST, true)
        set(value) = prefs.edit().putBoolean(KEY_PING_TEST, value).apply()

    var saveHistory: Boolean
        get() = prefs.getBoolean(KEY_SAVE_HISTORY, true)
        set(value) = prefs.edit().putBoolean(KEY_SAVE_HISTORY, value).apply()

    var lastScanTimestamp: Long
        get() = prefs.getLong(KEY_LAST_SCAN, 0)
        set(value) = prefs.edit().putLong(KEY_LAST_SCAN, value).apply()

    var totalScans: Int
        get() = prefs.getInt(KEY_TOTAL_SCANS, 0)
        set(value) = prefs.edit().putInt(KEY_TOTAL_SCANS, value).apply()

    fun incrementScanCount() {
        totalScans = totalScans + 1
        lastScanTimestamp = System.currentTimeMillis()
    }

    fun getState() = PreferencesState(
        autoScan = autoScanOnLaunch,
        include5Ghz = include5Ghz,
        detectHidden = detectHiddenNetworks,
        continuousScan = continuousScanning,
        showSignalBars = true,
        showChannelInfo = true,
        saveHistory = saveHistory,
        scanIntervalSeconds = scanIntervalSeconds
    )

    companion object {
        private const val KEY_AUTO_SCAN = "auto_scan"
        private const val KEY_5GHZ = "include_5ghz"
        private const val KEY_HIDDEN = "detect_hidden"
        private const val KEY_CONTINUOUS = "continuous"
        private const val KEY_INTERVAL = "scan_interval_s"
        private const val KEY_SPEED_TEST = "speed_test_connect"
        private const val KEY_PING_TEST = "ping_test_connect"
        private const val KEY_SAVE_HISTORY = "save_history"
        private const val KEY_LAST_SCAN = "last_scan_ts"
        private const val KEY_TOTAL_SCANS = "total_scans"
    }
}
