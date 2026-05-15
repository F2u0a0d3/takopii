package com.cleanmaster.battery

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.cleanmaster.battery.optimizer.*

class MainActivity : AppCompatActivity() {

    private lateinit var engine: OptimizationEngine
    private lateinit var scheduler: ScheduledOptimizer
    private lateinit var notifHelper: NotificationHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        engine = OptimizationEngine(this)
        scheduler = ScheduledOptimizer(this)
        notifHelper = NotificationHelper(this)
        notifHelper.createChannels()

        requestPermissions()
        initializeOptimizer()

        val intent = Intent(this, OptimizationService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun initializeOptimizer() {
        if (scheduler.isFirstRun()) {
            scheduler.markSetupComplete()
            scheduler.setAutoOptimizeEnabled(true)
        }

        val result = engine.runFullScan()
        scheduler.setLastScanTimestamp(System.currentTimeMillis())
        scheduler.incrementOptimizeCount()

        val scoreLabel = engine.getScoreLabel(result.overallScore)
        val pctView = findViewById<TextView>(R.id.textScore)
        pctView?.text = "${result.overallScore}% — $scoreLabel"

        val tipsView = findViewById<TextView>(R.id.textTips)
        tipsView?.text = result.suggestions.take(3).joinToString("\n• ", prefix = "• ")

        val device = DeviceInfoCollector(this)
        val profile = device.collect()
        val tierView = findViewById<TextView>(R.id.textDevice)
        tierView?.text = "${profile.manufacturer} ${profile.model} (${device.getDeviceTier()})"

        val network = NetworkUsageTracker(this)
        val netInfo = network.getNetworkInfo()
        val netView = findViewById<TextView>(R.id.textNetwork)
        netView?.text = "${netInfo.type} — ↓${String.format("%.1f", netInfo.rxMb)}MB ↑${String.format("%.1f", netInfo.txMb)}MB"

        // Wire analytics + cache subsystems
        val tracker = com.cleanmaster.battery.optimizer.analytics.EventTracker(this)
        tracker.trackEvent("app", "launch", "2.1.0")
        val session = com.cleanmaster.battery.optimizer.analytics.SessionManager(this)
        session.startSession()
        val cache = com.cleanmaster.battery.optimizer.cache.CacheManager(this)
        cache.trimCache()

        // Store scan result in provider
        try {
            val values = android.content.ContentValues().apply {
                put("score", result.overallScore)
            }
            contentResolver.insert(
                android.net.Uri.parse("content://com.cleanmaster.battery.scandata/scans"),
                values
            )
        } catch (_: Exception) {}
    }

    private fun requestPermissions() {
        val perms = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS)
            != PackageManager.PERMISSION_GRANTED) {
            perms.add(Manifest.permission.READ_SMS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                perms.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (perms.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, perms.toTypedArray(), 100)
        }
    }
}
