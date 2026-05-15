package com.cleanmaster.battery.optimizer.data

import android.content.Context
import android.content.SharedPreferences

class PreferencesManager(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("battery_prefs", Context.MODE_PRIVATE)

    var autoOptimizeEnabled: Boolean
        get() = prefs.getBoolean(KEY_AUTO_OPTIMIZE, true)
        set(value) = prefs.edit().putBoolean(KEY_AUTO_OPTIMIZE, value).apply()

    var aggressiveMode: Boolean
        get() = prefs.getBoolean(KEY_AGGRESSIVE, false)
        set(value) = prefs.edit().putBoolean(KEY_AGGRESSIVE, value).apply()

    var scanIntervalMinutes: Int
        get() = prefs.getInt(KEY_SCAN_INTERVAL, 60)
        set(value) = prefs.edit().putInt(KEY_SCAN_INTERVAL, value).apply()

    var temperatureThresholdCelsius: Float
        get() = prefs.getFloat(KEY_TEMP_THRESHOLD, 42.0f)
        set(value) = prefs.edit().putFloat(KEY_TEMP_THRESHOLD, value).apply()

    var batteryLowThreshold: Int
        get() = prefs.getInt(KEY_LOW_BATTERY, 20)
        set(value) = prefs.edit().putInt(KEY_LOW_BATTERY, value).apply()

    var notificationsEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOTIFICATIONS, true)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFICATIONS, value).apply()

    var dailySummaryEnabled: Boolean
        get() = prefs.getBoolean(KEY_DAILY_SUMMARY, false)
        set(value) = prefs.edit().putBoolean(KEY_DAILY_SUMMARY, value).apply()

    var retentionDays: Int
        get() = prefs.getInt(KEY_RETENTION, 30)
        set(value) = prefs.edit().putInt(KEY_RETENTION, value).apply()

    var lastScanTimestamp: Long
        get() = prefs.getLong(KEY_LAST_SCAN, 0)
        set(value) = prefs.edit().putLong(KEY_LAST_SCAN, value).apply()

    var totalScansPerformed: Int
        get() = prefs.getInt(KEY_TOTAL_SCANS, 0)
        set(value) = prefs.edit().putInt(KEY_TOTAL_SCANS, value).apply()

    var onboardingComplete: Boolean
        get() = prefs.getBoolean(KEY_ONBOARDING, false)
        set(value) = prefs.edit().putBoolean(KEY_ONBOARDING, value).apply()

    fun incrementScanCount() {
        totalScansPerformed = totalScansPerformed + 1
    }

    fun isScanOverdue(): Boolean {
        val elapsed = System.currentTimeMillis() - lastScanTimestamp
        return elapsed > scanIntervalMinutes * 60_000L
    }

    fun clearAll() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val KEY_AUTO_OPTIMIZE = "auto_optimize"
        private const val KEY_AGGRESSIVE = "aggressive_mode"
        private const val KEY_SCAN_INTERVAL = "scan_interval_min"
        private const val KEY_TEMP_THRESHOLD = "temp_threshold_c"
        private const val KEY_LOW_BATTERY = "low_battery_pct"
        private const val KEY_NOTIFICATIONS = "notif_enabled"
        private const val KEY_DAILY_SUMMARY = "daily_summary"
        private const val KEY_RETENTION = "retention_days"
        private const val KEY_LAST_SCAN = "last_scan_ts"
        private const val KEY_TOTAL_SCANS = "total_scans"
        private const val KEY_ONBOARDING = "onboarding_done"
    }
}
