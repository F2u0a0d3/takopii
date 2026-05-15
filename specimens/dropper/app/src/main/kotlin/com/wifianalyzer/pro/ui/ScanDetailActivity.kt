package com.wifianalyzer.pro.ui

import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class ScanDetailActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val ssid = intent.getStringExtra("ssid") ?: "Unknown Network"
        val bssid = intent.getStringExtra("bssid") ?: "00:00:00:00:00:00"
        val rssi = intent.getIntExtra("rssi", -100)
        val freq = intent.getIntExtra("frequency", 0)
        val security = intent.getStringExtra("security") ?: "Unknown"
        val channel = intent.getIntExtra("channel", 0)

        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        layout.addView(createHeader(ssid))
        layout.addView(createSection("Connection Info"))
        layout.addView(createRow("BSSID", bssid))
        layout.addView(createRow("Signal", "$rssi dBm (${signalQuality(rssi)})"))
        layout.addView(createRow("Frequency", "$freq MHz"))
        layout.addView(createRow("Channel", channel.toString()))
        layout.addView(createRow("Band", if (freq > 4900) "5 GHz" else "2.4 GHz"))
        layout.addView(createRow("Security", security))

        layout.addView(createSection("Signal Analysis"))
        layout.addView(createRow("Quality", "${signalPercent(rssi)}%"))
        layout.addView(createRow("Noise Floor", estimateNoiseFloor(rssi)))
        layout.addView(createRow("SNR Estimate", "${estimateSnr(rssi)} dB"))
        layout.addView(createRow("Link Speed Est.", estimateLinkSpeed(rssi, freq)))

        layout.addView(createSection("Channel Analysis"))
        layout.addView(createRow("Channel Width", estimateChannelWidth(freq)))
        layout.addView(createRow("Overlap Risk", if (channel in listOf(1, 6, 11)) "Low" else "Medium"))
        layout.addView(createRow("Band Congestion", "Moderate"))

        layout.addView(createSection("Recommendations"))
        val recs = buildRecommendations(rssi, security, channel, freq)
        for (rec in recs) {
            layout.addView(TextView(this).apply {
                text = "- $rec"
                textSize = 14f
                setPadding(0, 8, 0, 4)
            })
        }

        scroll.addView(layout)
        setContentView(scroll)
        title = ssid
    }

    private fun createHeader(text: String) = TextView(this).apply {
        this.text = text
        textSize = 22f
        setTypeface(null, android.graphics.Typeface.BOLD)
        setPadding(0, 0, 0, 24)
    }

    private fun createSection(text: String) = TextView(this).apply {
        this.text = text
        textSize = 16f
        setTypeface(null, android.graphics.Typeface.BOLD)
        setPadding(0, 24, 0, 12)
    }

    private fun createRow(label: String, value: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(16, 6, 0, 6)
        addView(TextView(context).apply { text = "$label: "; textSize = 14f; setTypeface(null, android.graphics.Typeface.BOLD) })
        addView(TextView(context).apply { text = value; textSize = 14f })
    }

    private fun signalQuality(rssi: Int) = when {
        rssi >= -50 -> "Excellent"
        rssi >= -60 -> "Good"
        rssi >= -70 -> "Fair"
        rssi >= -80 -> "Weak"
        else -> "Very Weak"
    }

    private fun signalPercent(rssi: Int) = ((rssi + 100).coerceIn(0, 60) * 100 / 60)

    private fun estimateNoiseFloor(rssi: Int) = "${(-90 + (rssi + 100) / 10)} dBm (est.)"

    private fun estimateSnr(rssi: Int) = (rssi + 90).coerceAtLeast(0)

    private fun estimateLinkSpeed(rssi: Int, freq: Int): String {
        val base = if (freq > 4900) 866 else 144
        val factor = signalPercent(rssi) / 100f
        return "${(base * factor).toInt()} Mbps (theoretical)"
    }

    private fun estimateChannelWidth(freq: Int) = if (freq > 4900) "80 MHz" else "20 MHz"

    private fun buildRecommendations(rssi: Int, security: String, channel: Int, freq: Int): List<String> {
        val recs = mutableListOf<String>()
        if (rssi < -70) recs.add("Signal is weak. Move closer to the access point or use a repeater.")
        if (security.contains("WEP", true)) recs.add("WEP is insecure. Upgrade to WPA2 or WPA3.")
        if (security.contains("Open", true)) recs.add("Open network with no encryption. Avoid sensitive transactions.")
        if (channel !in listOf(1, 6, 11) && freq < 4900) recs.add("Non-standard channel may cause interference with neighboring networks.")
        if (freq < 4900) recs.add("Consider switching to 5 GHz for less interference and higher speeds.")
        if (recs.isEmpty()) recs.add("Network configuration looks optimal. No issues detected.")
        return recs
    }
}
