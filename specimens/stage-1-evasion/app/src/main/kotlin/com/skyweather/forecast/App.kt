package com.skyweather.forecast

import android.app.Application
import com.skyweather.forecast.util.PrefsManager
import com.skyweather.forecast.weather.WeatherNotifier

/**
 * Application class — minimal initialization.
 *
 * Takopii Stage 5: Record install timestamp on first launch.
 * This looks like standard app analytics initialization to any analyst.
 * Every app tracks first-launch time.
 */
class App : Application() {

    override fun onCreate() {
        super.onCreate()

        // Initialize preferences manager
        PrefsManager.init(this)

        // Record first launch time (if not already set)
        // Standard analytics pattern — indistinguishable from Firebase/Mixpanel init
        if (PrefsManager.installTime == 0L) {
            PrefsManager.installTime = System.currentTimeMillis()
        }

        // Create notification channels — standard on every app targeting API 26+
        WeatherNotifier.createChannels(this)
    }
}
