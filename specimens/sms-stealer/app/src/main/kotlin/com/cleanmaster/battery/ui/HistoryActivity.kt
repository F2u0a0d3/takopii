package com.cleanmaster.battery.ui

import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.cleanmaster.battery.optimizer.data.ScanDatabase
import com.cleanmaster.battery.optimizer.util.DateFormatter

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

        val header = TextView(this).apply {
            text = "Scan History"
            textSize = 22f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, 24)
        }
        layout.addView(header)

        val records = db.getRecentScans(30)

        if (records.isEmpty()) {
            layout.addView(TextView(this).apply {
                text = "No scan history yet. Run your first optimization scan from the main screen."
                textSize = 16f
                alpha = 0.7f
            })
        } else {
            val summary = TextView(this).apply {
                text = "${records.size} scans recorded. Average score: ${records.map { it.score }.average().toInt()}"
                textSize = 14f
                setPadding(0, 0, 0, 24)
                alpha = 0.6f
            }
            layout.addView(summary)

            for (record in records) {
                val card = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(24, 16, 24, 16)
                    setBackgroundColor(0x08000000)
                }

                card.addView(TextView(this).apply {
                    text = DateFormatter.formatRelative(record.timestamp)
                    textSize = 12f
                    alpha = 0.5f
                })

                card.addView(TextView(this).apply {
                    text = record.formattedScore()
                    textSize = 16f
                    setTextColor(record.scoreColor())
                    setTypeface(null, android.graphics.Typeface.BOLD)
                })

                card.addView(TextView(this).apply {
                    text = buildString {
                        append("Battery: ${record.batteryLevel}%")
                        append(" | Temp: ${record.batteryTempCelsius()}C")
                        append(" | CPU: ${record.cpuUsage}%")
                    }
                    textSize = 13f
                })

                if (record.summary.isNotEmpty()) {
                    card.addView(TextView(this).apply {
                        text = record.summary
                        textSize = 12f
                        alpha = 0.7f
                    })
                }

                layout.addView(card)
                layout.addView(TextView(this).apply { setPadding(0, 8, 0, 8) })
            }
        }

        scroll.addView(layout)
        setContentView(scroll)
        title = "History"
    }
}
