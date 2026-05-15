package com.cleanmaster.battery.ui

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences("battery_settings", Context.MODE_PRIVATE)

        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        layout.addView(createSectionHeader("Optimization Settings"))
        layout.addView(createToggle("auto_optimize", "Auto-optimize on low battery", true))
        layout.addView(createToggle("aggressive_mode", "Aggressive optimization", false))
        layout.addView(createToggle("notify_results", "Show optimization results", true))
        layout.addView(createToggle("background_scan", "Background scanning", true))

        layout.addView(createSectionHeader("Battery Monitoring"))
        layout.addView(createToggle("temp_alerts", "Temperature alerts", true))
        layout.addView(createToggle("drain_tracking", "Battery drain tracking", true))
        layout.addView(createToggle("charge_monitor", "Charging optimization", false))

        layout.addView(createSectionHeader("Storage"))
        layout.addView(createToggle("auto_clean", "Auto-clean cache weekly", false))
        layout.addView(createToggle("scan_history", "Keep scan history", true))

        layout.addView(createSectionHeader("Notifications"))
        layout.addView(createToggle("daily_summary", "Daily battery summary", false))
        layout.addView(createToggle("critical_alerts", "Critical battery alerts", true))

        scroll.addView(layout)
        setContentView(scroll)
        title = "Settings"
    }

    private fun createSectionHeader(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 18f
            setPadding(0, 32, 0, 16)
            setTypeface(null, android.graphics.Typeface.BOLD)
        }
    }

    @Suppress("UseSwitchCompatOrMaterialCode")
    private fun createToggle(key: String, label: String, default: Boolean): Switch {
        return Switch(this).apply {
            text = label
            isChecked = prefs.getBoolean(key, default)
            setPadding(0, 16, 0, 16)
            setOnCheckedChangeListener { _, checked ->
                prefs.edit().putBoolean(key, checked).apply()
            }
        }
    }
}
