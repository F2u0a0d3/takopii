package com.wifianalyzer.pro.ui

import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.wifianalyzer.pro.scanner.data.ScanDatabase
import com.wifianalyzer.pro.scanner.util.DateFormatter

class HistoryActivity : AppCompatActivity() {

    private lateinit var db: ScanDatabase

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = ScanDatabase(this)

        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        layout.addView(TextView(this).apply {
            text = "Scan History"
            textSize = 22f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, 24)
        })

        val records = db.getRecentScans(50)

        if (records.isEmpty()) {
            layout.addView(TextView(this).apply {
                text = "No scan history yet. Perform a WiFi scan from the main screen."
                textSize = 16f; alpha = 0.7f
            })
        } else {
            layout.addView(TextView(this).apply {
                text = "${records.size} scans recorded"
                textSize = 14f; alpha = 0.6f; setPadding(0, 0, 0, 24)
            })
            for (rec in records) {
                val card = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(24, 16, 24, 16)
                    setBackgroundColor(0x08000000)
                }
                card.addView(TextView(this).apply {
                    text = DateFormatter.formatRelative(rec.timestamp)
                    textSize = 12f; alpha = 0.5f
                })
                card.addView(TextView(this).apply {
                    text = "Networks found: ${rec.networkCount}"
                    textSize = 16f
                    setTypeface(null, android.graphics.Typeface.BOLD)
                })
                card.addView(TextView(this).apply {
                    text = "Best: ${rec.bestSignalDbm} dBm | Avg: ${rec.avgSignalDbm} dBm | Connected: ${rec.connectedSsid}"
                    textSize = 13f
                })
                layout.addView(card)
                layout.addView(TextView(this).apply { setPadding(0, 8, 0, 8) })
            }
        }

        scroll.addView(layout)
        setContentView(scroll)
        title = "Scan History"
    }
}
