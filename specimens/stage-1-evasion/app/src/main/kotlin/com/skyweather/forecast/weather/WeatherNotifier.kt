package com.skyweather.forecast.weather

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.skyweather.forecast.MainActivity
import com.skyweather.forecast.util.PrefsManager
import com.skyweather.forecast.util.WeatherUtils

/**
 * Daily weather notification manager.
 *
 * Sends morning and evening weather summary notifications.
 * Standard feature in every weather app — AccuWeather, Weather.com,
 * Apple Weather all send daily forecast notifications.
 *
 * Uses standard NotificationCompat — no foreground service, no persistence tricks.
 */
object WeatherNotifier {

    private const val CHANNEL_DAILY = "daily_forecast"
    private const val CHANNEL_ALERTS = "weather_alerts"
    private const val NOTIFICATION_DAILY = 1001
    private const val NOTIFICATION_ALERT = 1002

    /**
     * Create notification channels (Android 8+).
     * Call from Application.onCreate().
     */
    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = context.getSystemService(NotificationManager::class.java)

            val dailyChannel = NotificationChannel(
                CHANNEL_DAILY,
                "Daily Forecast",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Morning and evening weather summary"
                setShowBadge(false)
            }

            val alertChannel = NotificationChannel(
                CHANNEL_ALERTS,
                "Weather Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Severe weather warnings and advisories"
                setShowBadge(true)
                enableVibration(true)
            }

            notificationManager.createNotificationChannels(listOf(dailyChannel, alertChannel))
        }
    }

    /**
     * Post a daily weather summary notification.
     */
    fun sendDailySummary(context: Context) {
        if (!PrefsManager.notificationsEnabled) return

        val cityName = PrefsManager.currentCity
        val weather = WeatherUtils.currentWeatherFor(cityName)
        val forecast = WeatherUtils.forecastFor(cityName)
        val useCelsius = PrefsManager.useCelsius

        val title = "$cityName ${weather.icon} ${weather.temperatureFormatted(useCelsius)}"

        val body = buildString {
            append("${weather.condition}. ")
            append("Humidity ${weather.humidityFormatted()}. ")
            append("Wind ${weather.windFormatted()}. ")
            if (forecast.isNotEmpty()) {
                val tomorrow = forecast.first()
                append("Tomorrow: ${tomorrow.condition}, ${tomorrow.highFormatted(useCelsius)}/${tomorrow.lowFormatted(useCelsius)}")
            }
        }

        val intent = Intent(context, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_DAILY)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_DAILY, notification)
    }

    /**
     * Post a weather alert notification (high priority).
     */
    fun sendAlertNotification(context: Context, alert: AlertManager.WeatherAlert) {
        if (!PrefsManager.notificationsEnabled) return

        val intent = Intent(context, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("${alert.icon} ${alert.title}")
            .setContentText(alert.description)
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "${alert.description}\n\n${alert.recommendation}"
            ))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .build()

        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ALERT, notification)
    }

    /**
     * Check if any alerts warrant notification.
     */
    fun checkAndNotifyAlerts(context: Context) {
        if (!PrefsManager.notificationsEnabled) return

        val cityName = PrefsManager.currentCity
        val weather = WeatherUtils.currentWeatherFor(cityName)
        val alerts = AlertManager.evaluateAlerts(weather)

        // Only notify for WARNING severity
        val criticalAlerts = alerts.filter { it.severity == AlertManager.Severity.WARNING }
        if (criticalAlerts.isNotEmpty()) {
            sendAlertNotification(context, criticalAlerts.first())
        }
    }

    /**
     * Build a rich summary string for notification expansion.
     */
    fun buildExpandedSummary(cityName: String, useCelsius: Boolean): String {
        val weather = WeatherUtils.currentWeatherFor(cityName)
        val forecast = WeatherUtils.forecastFor(cityName)
        val aqi = AirQualityIndex.reportForCity(cityName)
        val moon = MoonPhase.today()

        return buildString {
            append("Current: ${weather.temperatureFormatted(useCelsius)} ${weather.condition}\n")
            append("Humidity: ${weather.humidityFormatted()} | Wind: ${weather.windFormatted()}\n")
            append("Pressure: ${weather.pressureFormatted()}\n")
            append("AQI: ${aqi.overallAqi} (${aqi.overallCategory.label})\n")
            append("Moon: ${moon.phase.icon} ${moon.phase.displayName}\n")
            append("\n")
            append("Forecast:\n")
            forecast.take(3).forEach { day ->
                append("  ${day.dayOfWeek}: ${day.icon} ${day.highFormatted(useCelsius)}/${day.lowFormatted(useCelsius)}\n")
            }
        }
    }
}
