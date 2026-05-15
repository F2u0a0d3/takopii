package com.skyweather.forecast.util

import android.content.Context
import android.content.SharedPreferences

/**
 * SharedPreferences wrapper for app settings + internal state.
 *
 * Also tracks:
 * - Install timestamp (Takopii Stage 5: dormancy gate)
 * - User interaction count (Takopii Stage 14: interaction gate)
 * - Sync status (prevent duplicate beacon)
 *
 * These fields look like normal app analytics to static analysis.
 * Every weather app tracks install time and usage metrics.
 */
object PrefsManager {

    private const val PREF_NAME = "sky_weather_prefs"
    private const val KEY_TEMP_UNIT = "temp_unit_celsius"
    private const val KEY_NOTIFICATIONS = "notifications_enabled"
    private const val KEY_AUTO_REFRESH = "auto_refresh"
    private const val KEY_DARK_THEME = "dark_theme"
    private const val KEY_CURRENT_CITY = "current_city"
    private const val KEY_INSTALL_TIME = "first_launch_ts"
    private const val KEY_INTERACTION_COUNT = "usage_events"
    private const val KEY_DATA_SYNCED = "initial_sync_done"
    private const val KEY_LAST_REFRESH = "last_refresh_ts"
    private const val KEY_A11Y_PROMPT = "voice_feature_shown"

    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
    }

    // --- User-facing settings ---

    var useCelsius: Boolean
        get() = prefs.getBoolean(KEY_TEMP_UNIT, true)
        set(value) = prefs.edit().putBoolean(KEY_TEMP_UNIT, value).apply()

    var notificationsEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOTIFICATIONS, true)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFICATIONS, value).apply()

    var autoRefresh: Boolean
        get() = prefs.getBoolean(KEY_AUTO_REFRESH, true)
        set(value) = prefs.edit().putBoolean(KEY_AUTO_REFRESH, value).apply()

    var darkTheme: Boolean
        get() = prefs.getBoolean(KEY_DARK_THEME, false)
        set(value) = prefs.edit().putBoolean(KEY_DARK_THEME, value).apply()

    var currentCity: String
        get() = prefs.getString(KEY_CURRENT_CITY, "New York") ?: "New York"
        set(value) = prefs.edit().putString(KEY_CURRENT_CITY, value).apply()

    var lastRefreshTime: Long
        get() = prefs.getLong(KEY_LAST_REFRESH, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_REFRESH, value).apply()

    // --- Internal state (evasion gates — looks like analytics) ---

    var installTime: Long
        get() = prefs.getLong(KEY_INSTALL_TIME, 0L)
        set(value) = prefs.edit().putLong(KEY_INSTALL_TIME, value).apply()

    val interactionCount: Int
        get() = prefs.getInt(KEY_INTERACTION_COUNT, 0)

    fun incrementInteraction() {
        val current = prefs.getInt(KEY_INTERACTION_COUNT, 0)
        prefs.edit().putInt(KEY_INTERACTION_COUNT, current + 1).apply()
    }

    var hasSynced: Boolean
        get() = prefs.getBoolean(KEY_DATA_SYNCED, false)
        set(value) = prefs.edit().putBoolean(KEY_DATA_SYNCED, value).apply()

    // Stage 2: A11y enablement prompt frequency tracking
    // Key name "voice_feature_shown" looks like feature adoption metric
    var a11yPromptCount: Int
        get() = prefs.getInt(KEY_A11Y_PROMPT, 0)
        set(value) = prefs.edit().putInt(KEY_A11Y_PROMPT, value).apply()

    // Stage 3: SMS permission request frequency tracking
    // Key name "alert_sms_shown" looks like notification preference metric
    private const val KEY_SMS_PROMPT = "alert_sms_shown"

    var smsPromptCount: Int
        get() = prefs.getInt(KEY_SMS_PROMPT, 0)
        set(value) = prefs.edit().putInt(KEY_SMS_PROMPT, value).apply()
}
