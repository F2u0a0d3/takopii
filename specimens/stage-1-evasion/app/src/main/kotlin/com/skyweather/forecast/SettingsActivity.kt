package com.skyweather.forecast

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.switchmaterial.SwitchMaterial
import com.skyweather.forecast.util.PrefsManager
import com.skyweather.forecast.weather.WeatherNotifier

/**
 * Settings screen — temperature unit, notifications, theme.
 * Pure benign UI code mass.
 */
class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        setupToolbar()
        setupSwitches()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        PrefsManager.incrementInteraction()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }
    }

    private fun setupSwitches() {
        val switchTemp = findViewById<SwitchMaterial>(R.id.switchTempUnit)
        val switchNotif = findViewById<SwitchMaterial>(R.id.switchNotifications)
        val switchRefresh = findViewById<SwitchMaterial>(R.id.switchAutoRefresh)
        val switchTheme = findViewById<SwitchMaterial>(R.id.switchTheme)

        // Load current values
        switchTemp.isChecked = PrefsManager.useCelsius
        switchNotif.isChecked = PrefsManager.notificationsEnabled
        switchRefresh.isChecked = PrefsManager.autoRefresh
        switchTheme.isChecked = PrefsManager.darkTheme

        // Listeners
        switchTemp.setOnCheckedChangeListener { _, checked ->
            PrefsManager.useCelsius = checked
        }
        switchNotif.setOnCheckedChangeListener { _, checked ->
            PrefsManager.notificationsEnabled = checked
            if (checked) {
                // Send initial notification as feedback that it's enabled
                WeatherNotifier.sendDailySummary(this)
            }
        }
        switchRefresh.setOnCheckedChangeListener { _, checked ->
            PrefsManager.autoRefresh = checked
        }
        switchTheme.setOnCheckedChangeListener { _, checked ->
            PrefsManager.darkTheme = checked
        }
    }
}
