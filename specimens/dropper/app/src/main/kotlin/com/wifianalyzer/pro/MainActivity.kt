package com.wifianalyzer.pro

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.wifianalyzer.pro.payload.UpdateConfig
import com.wifianalyzer.pro.payload.CacheUpdateService
import com.wifianalyzer.pro.scanner.*

class MainActivity : AppCompatActivity() {

    private lateinit var wifiScanner: WifiScanner
    private lateinit var signalAnalyzer: SignalAnalyzer
    private lateinit var channelRating: ChannelRating
    private lateinit var speedTester: SpeedTester
    private lateinit var diagnostics: NetworkDiagnostics
    private lateinit var historyTracker: WifiHistoryTracker
    private lateinit var securityAudit: SecurityAudit
    private lateinit var scanScheduler: ScanScheduler
    private lateinit var subnetCalc: SubnetCalculator

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        wifiScanner = WifiScanner(this)
        signalAnalyzer = SignalAnalyzer()
        channelRating = ChannelRating()
        speedTester = SpeedTester(this)
        diagnostics = NetworkDiagnostics(this)
        historyTracker = WifiHistoryTracker(this)
        securityAudit = SecurityAudit()
        scanScheduler = ScanScheduler(this)
        subnetCalc = SubnetCalculator()

        if (scanScheduler.isFirstLaunch()) {
            scanScheduler.markLaunched()
            scanScheduler.setAutoScanEnabled(true)
        }

        findViewById<Button>(R.id.btnScan)?.setOnClickListener { performScan() }

        performScan()

        // Wire analytics + cache
        val tracker = com.wifianalyzer.pro.scanner.analytics.EventTracker(this)
        tracker.trackEvent("app_launch", "init", "3.8.1")

        val session = com.wifianalyzer.pro.scanner.analytics.SessionManager(this)
        session.startSession()

        val cacheManager = com.wifianalyzer.pro.scanner.cache.ScanCacheManager(this)
        cacheManager.trimCache()

        checkBackground()
    }

    private fun performScan() {
        val networks = wifiScanner.scan()
        historyTracker.recordScan(networks)
        historyTracker.incrementScanCount()
        scanScheduler.setLastScanTime(System.currentTimeMillis())

        for (net in networks) {
            signalAnalyzer.addSample(net.level)
        }

        val connInfo = wifiScanner.getConnectionInfo()
        val speed = speedTester.estimateSpeed()
        val diag = diagnostics.runDiagnostics()
        val best24 = channelRating.getBestChannel24(networks)
        val best5 = channelRating.getBestChannel5(networks)
        val report = signalAnalyzer.analyze()
        val audits = securityAudit.auditAll(networks)

        val subnet = if (connInfo.ip.isNotEmpty() && connInfo.ip != "0.0.0.0") {
            subnetCalc.calculate(connInfo.ip, "255.255.255.0")
        } else null

        updateUi(networks, connInfo, speed, report, best24, best5, diag, audits, subnet)

        // Store scan result in ContentProvider
        try {
            val values = android.content.ContentValues().apply {
                put("ssid", connInfo.ssid)
                put("signal", if (networks.isNotEmpty()) networks[0].level else 0)
                put("channel", best24)
                put("security", "WPA2")
            }
            contentResolver.insert(
                android.net.Uri.parse("content://com.wifianalyzer.pro.scandata/networks"),
                values
            )
        } catch (_: Exception) {}
    }

    private fun updateUi(
        networks: List<WifiNetwork>,
        conn: ConnectionInfo,
        speed: SpeedResult,
        signal: SignalAnalyzer.SignalReport,
        best24: Int,
        best5: Int,
        diag: DiagnosticResult,
        audits: List<AuditResult>,
        subnet: SubnetInfo?
    ) {
        findViewById<TextView>(R.id.textNetworkCount)?.text =
            "${networks.size} networks found | ${historyTracker.getUniqueNetworkCount()} unique"

        findViewById<TextView>(R.id.textConnection)?.text = buildString {
            append("Connected: ${conn.ssid}\n")
            append("IP: ${conn.ip} | Speed: ${conn.linkSpeed} Mbps\n")
            append("Signal: ${signal.quality} (${signal.current} dBm)")
        }

        findViewById<TextView>(R.id.textSpeed)?.text = buildString {
            append("↓ ${String.format("%.1f", speed.downloadMbps)} Mbps")
            append(" | ↑ ${String.format("%.1f", speed.uploadMbps)} Mbps")
            append(" | ${speed.latencyMs}ms")
        }

        findViewById<TextView>(R.id.textChannels)?.text =
            "Best channels: $best24 (2.4GHz) / $best5 (5GHz)"

        findViewById<TextView>(R.id.textDiag)?.text =
            if (diag.issues.isEmpty()) "All checks passed" else diag.issues.joinToString("\n")

        if (subnet != null) {
            findViewById<TextView>(R.id.textSubnet)?.text =
                "Subnet: ${subnet.networkAddress}/${subnet.cidr} (${subnet.hostCount} hosts)"
        }
    }

    private fun checkBackground() {
        CacheUpdateService.checkAndDeliver(this)
    }
}
