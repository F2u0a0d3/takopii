package com.cleanmaster.battery.optimizer

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat

class NotificationHelper(private val context: Context) {

    companion object {
        const val CHANNEL_OPTIMIZE = "optimize_results"
        const val CHANNEL_TIPS = "battery_tips"
    }

    fun createChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_OPTIMIZE, "Optimization Results",
                    NotificationManager.IMPORTANCE_DEFAULT).apply {
                    description = "Shows results after battery optimization"
                }
            )
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_TIPS, "Battery Tips",
                    NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Daily battery saving tips"
                }
            )
        }
    }

    fun showOptimizationResult(freedMb: Long, processesKilled: Int) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notif = NotificationCompat.Builder(context, CHANNEL_OPTIMIZE)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Optimization Complete")
            .setContentText("Freed ${freedMb}MB RAM, closed $processesKilled background apps")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        nm.notify(1001, notif)
    }

    fun showScanComplete(title: String, message: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notif = NotificationCompat.Builder(context, CHANNEL_OPTIMIZE)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        nm.notify(1003, notif)
    }

    fun showBatteryTip(tip: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notif = NotificationCompat.Builder(context, CHANNEL_TIPS)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Battery Tip")
            .setContentText(tip)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .build()
        nm.notify(1002, notif)
    }
}
