package com.docreader.lite.reader

import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * Foreground service — keeps the process alive.
 *
 * Real banker uses FG service with misleading notification:
 *   "Syncing documents..." or "Optimizing battery..."
 * This prevents Android from killing the process during Doze.
 *
 * The notification must exist (Android 8+ requirement for FG services)
 * but is LOW importance → barely visible to user.
 */
class BackgroundSyncService : Service() {

    companion object {
        fun start(context: Context) {
            val intent = Intent(context, BackgroundSyncService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        val notification = NotificationCompat.Builder(this, "doc_sync")
            .setContentTitle("Doc Reader Lite")
            .setContentText("Syncing documents...")
            .setSmallIcon(android.R.drawable.ic_menu_save)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()

        startForeground(1001, notification)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY // Restart if killed
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
