package com.cleanmaster.battery.ui

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.StatFs
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.cleanmaster.battery.R

class DiagnosticsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        runDiagnostics()
    }

    private fun runDiagnostics() {
        val results = mutableListOf<DiagnosticEntry>()
        results.add(checkMemory())
        results.add(checkStorage())
        results.add(checkBattery())
        results.add(checkNetwork())
        results.add(checkThermal())
        results.add(checkProcesses())
        results.add(checkCpuUsage())
        results.add(checkScreenBrightness())

        val summary = results.joinToString("\n") { "${it.category}: ${it.status} — ${it.detail}" }
        findViewById<TextView>(R.id.textScore)?.text = summary

        val score = calculateHealthScore(results)
        val prefs = getSharedPreferences("diagnostics", MODE_PRIVATE)
        prefs.edit()
            .putInt("last_score", score)
            .putLong("last_run", System.currentTimeMillis())
            .putInt("run_count", prefs.getInt("run_count", 0) + 1)
            .apply()
    }

    private fun checkMemory(): DiagnosticEntry {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        val totalMb = memInfo.totalMem / (1024 * 1024)
        val availMb = memInfo.availMem / (1024 * 1024)
        val usedPct = ((totalMb - availMb) * 100 / totalMb).toInt()
        val status = when {
            usedPct > 90 -> "Critical"
            usedPct > 75 -> "Warning"
            else -> "Normal"
        }
        return DiagnosticEntry("Memory", status, "${availMb}MB free of ${totalMb}MB ($usedPct% used)")
    }

    private fun checkStorage(): DiagnosticEntry {
        val stat = StatFs(Environment.getDataDirectory().path)
        val totalBytes = stat.totalBytes
        val freeBytes = stat.freeBytes
        val usedPct = ((totalBytes - freeBytes) * 100 / totalBytes).toInt()
        val freeGb = freeBytes / (1024.0 * 1024.0 * 1024.0)
        val status = when {
            freeGb < 1.0 -> "Critical"
            freeGb < 5.0 -> "Warning"
            else -> "Normal"
        }
        return DiagnosticEntry("Storage", status, String.format("%.1f GB free (%d%% used)", freeGb, usedPct))
    }

    private fun checkBattery(): DiagnosticEntry {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val batteryStatus = registerReceiver(null, filter)
        val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryStatus?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
        val pct = (level * 100) / scale
        val temp = (batteryStatus?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) ?: 0) / 10.0
        val plugged = batteryStatus?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0
        val charging = plugged != 0
        val status = when {
            temp > 45.0 -> "Critical"
            pct < 15 && !charging -> "Warning"
            temp > 38.0 -> "Warning"
            else -> "Normal"
        }
        return DiagnosticEntry("Battery", status, "${pct}% | ${temp}°C | ${if (charging) "Charging" else "Discharging"}")
    }

    private fun checkNetwork(): DiagnosticEntry {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = if (network != null) cm.getNetworkCapabilities(network) else null
        return if (caps != null) {
            val type = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                else -> "Other"
            }
            val downMbps = caps.linkDownstreamBandwidthKbps / 1000
            DiagnosticEntry("Network", "Connected", "$type ($downMbps Mbps)")
        } else {
            DiagnosticEntry("Network", "Disconnected", "No active connection")
        }
    }

    private fun checkThermal(): DiagnosticEntry {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            val thermal = pm.currentThermalStatus
            val label = when (thermal) {
                0 -> "None"
                1 -> "Light"
                2 -> "Moderate"
                3 -> "Severe"
                4 -> "Critical"
                5 -> "Emergency"
                6 -> "Shutdown"
                else -> "Unknown"
            }
            val status = if (thermal >= 3) "Warning" else "Normal"
            DiagnosticEntry("Thermal", status, "Status: $label ($thermal)")
        } else {
            DiagnosticEntry("Thermal", "N/A", "Requires Android 10+")
        }
    }

    private fun checkProcesses(): DiagnosticEntry {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val running = am.runningAppProcesses?.size ?: 0
        val status = when {
            running > 100 -> "Warning"
            running > 200 -> "Critical"
            else -> "Normal"
        }
        return DiagnosticEntry("Processes", status, "$running active processes")
    }

    private fun checkCpuUsage(): DiagnosticEntry {
        return try {
            val cores = Runtime.getRuntime().availableProcessors()
            val maxMem = Runtime.getRuntime().maxMemory() / (1024 * 1024)
            DiagnosticEntry("CPU", "Normal", "$cores cores, ${maxMem}MB max heap")
        } catch (e: Exception) {
            DiagnosticEntry("CPU", "Error", e.message ?: "Unknown")
        }
    }

    private fun checkScreenBrightness(): DiagnosticEntry {
        return try {
            val brightness = android.provider.Settings.System.getInt(
                contentResolver,
                android.provider.Settings.System.SCREEN_BRIGHTNESS,
                128
            )
            val pct = (brightness * 100) / 255
            val status = if (pct > 80) "Warning" else "Normal"
            DiagnosticEntry("Display", status, "Brightness: $pct%")
        } catch (e: Exception) {
            DiagnosticEntry("Display", "N/A", "Cannot read brightness")
        }
    }

    private fun calculateHealthScore(entries: List<DiagnosticEntry>): Int {
        var score = 100
        for (entry in entries) {
            when (entry.status) {
                "Critical" -> score -= 25
                "Warning" -> score -= 10
                "Error" -> score -= 5
            }
        }
        return score.coerceIn(0, 100)
    }

    data class DiagnosticEntry(
        val category: String,
        val status: String,
        val detail: String
    )
}
