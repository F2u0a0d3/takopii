package com.wifianalyzer.pro.ui

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
        prefs = getSharedPreferences("wifi_settings", Context.MODE_PRIVATE)

        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        layout.addView(createSectionHeader("Scan Settings"))
        layout.addView(createToggle("auto_scan", "Auto-scan on launch", true))
        layout.addView(createToggle("scan_5ghz", "Include 5 GHz networks", true))
        layout.addView(createToggle("scan_hidden", "Detect hidden networks", false))
        layout.addView(createToggle("continuous_scan", "Continuous scanning", false))

        layout.addView(createSectionHeader("Display"))
        layout.addView(createToggle("signal_bars", "Show signal strength bars", true))
        layout.addView(createToggle("channel_info", "Show channel information", true))
        layout.addView(createToggle("vendor_lookup", "Show device manufacturer", false))
        layout.addView(createToggle("ip_info", "Show IP details", true))

        layout.addView(createSectionHeader("Network Analysis"))
        layout.addView(createToggle("speed_test", "Auto speed test on connect", false))
        layout.addView(createToggle("ping_test", "Latency test on connect", true))
        layout.addView(createToggle("dns_check", "DNS resolution check", true))

        layout.addView(createSectionHeader("Notifications"))
        layout.addView(createToggle("weak_signal", "Weak signal alerts", false))
        layout.addView(createToggle("new_network", "New network detected", false))
        layout.addView(createToggle("connection_drop", "Connection drop alerts", true))

        layout.addView(createSectionHeader("History"))
        layout.addView(createToggle("save_history", "Save scan history", true))
        layout.addView(createToggle("auto_cleanup", "Auto-clean old records", true))

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
