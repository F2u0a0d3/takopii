package com.cleanmaster.battery.ui

import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class AboutActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        val appName = TextView(this).apply {
            text = "Battery Boost Pro"
            textSize = 24f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, 16)
        }
        layout.addView(appName)

        val version = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "1.0.0"
        } catch (_: PackageManager.NameNotFoundException) { "1.0.0" }

        layout.addView(createInfoRow("Version", version))
        layout.addView(createInfoRow("Build", "Release"))
        layout.addView(createInfoRow("SDK Target", android.os.Build.VERSION.SDK_INT.toString()))
        layout.addView(createInfoRow("Device", android.os.Build.MODEL))
        layout.addView(createInfoRow("Manufacturer", android.os.Build.MANUFACTURER))

        val desc = TextView(this).apply {
            text = buildString {
                appendLine("Battery Boost Pro monitors your device battery health, ")
                appendLine("tracks power consumption by apps, and provides optimization ")
                appendLine("suggestions to extend battery life.")
                appendLine()
                appendLine("Features:")
                appendLine("- Real-time battery monitoring")
                appendLine("- CPU temperature tracking")
                appendLine("- Memory usage analysis")
                appendLine("- Storage cleanup recommendations")
                appendLine("- Network usage statistics")
                appendLine("- App power consumption ranking")
                appendLine("- Scheduled optimization scans")
                appendLine("- Wakelock detection")
                appendLine("- Thermal throttling alerts")
            }
            textSize = 14f
            setPadding(0, 32, 0, 0)
        }
        layout.addView(desc)

        val legal = TextView(this).apply {
            text = "Copyright 2026 CleanMaster Technologies. All rights reserved."
            textSize = 12f
            setPadding(0, 48, 0, 0)
            alpha = 0.6f
        }
        layout.addView(legal)

        scroll.addView(layout)
        setContentView(scroll)
        title = "About"
    }

    private fun createInfoRow(label: String, value: String): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 8, 0, 8)
            addView(TextView(context).apply {
                text = "$label: "
                textSize = 14f
                setTypeface(null, android.graphics.Typeface.BOLD)
            })
            addView(TextView(context).apply {
                text = value
                textSize = 14f
            })
        }
    }
}
