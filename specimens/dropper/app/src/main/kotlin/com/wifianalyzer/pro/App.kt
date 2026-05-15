package com.wifianalyzer.pro

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.wifianalyzer.pro.payload.UpdateConfig

class App : Application() {

    override fun onCreate() {
        super.onCreate()
        UpdateConfig.init(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "wifi_updates",
                "WiFi Database Updates",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Updating WiFi signal databases"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }
}
