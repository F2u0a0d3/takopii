package com.wifianalyzer.pro.ui

import android.content.pm.PackageManager
import android.os.Build
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

        layout.addView(TextView(this).apply {
            text = "WiFi Analyzer Pro"
            textSize = 24f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, 16)
        })

        val version = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "3.8.1"
        } catch (_: PackageManager.NameNotFoundException) { "3.8.1" }

        layout.addView(createInfoRow("Version", version))
        layout.addView(createInfoRow("Build Type", "Release"))
        layout.addView(createInfoRow("Android", "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"))
        layout.addView(createInfoRow("Device", "${Build.MANUFACTURER} ${Build.MODEL}"))

        layout.addView(TextView(this).apply {
            text = buildString {
                appendLine("WiFi Analyzer Pro is a comprehensive wireless network analysis tool ")
                appendLine("designed for network administrators and enthusiasts.")
                appendLine()
                appendLine("Features:")
                appendLine("- Scan and discover nearby WiFi networks")
                appendLine("- Analyze signal strength and quality")
                appendLine("- Channel interference detection")
                appendLine("- Network speed estimation")
                appendLine("- Connection diagnostics")
                appendLine("- WiFi security auditing (WEP/WPA/WPA2/WPA3)")
                appendLine("- Subnet calculator")
                appendLine("- Ping and latency testing")
                appendLine("- Bandwidth estimation")
                appendLine("- Network history tracking")
                appendLine("- DNS resolver testing")
                appendLine("- Router detection")
            }
            textSize = 14f
            setPadding(0, 32, 0, 0)
        })

        layout.addView(TextView(this).apply {
            text = "Copyright 2026 WiFi Analyzer Pro. All rights reserved."
            textSize = 12f
            setPadding(0, 48, 0, 0)
            alpha = 0.6f
        })

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
            addView(TextView(context).apply { text = value; textSize = 14f })
        }
    }
}
