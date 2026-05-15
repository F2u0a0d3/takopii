package com.skyweather.forecast.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.skyweather.forecast.MainActivity
import com.skyweather.forecast.R
import com.skyweather.forecast.util.PrefsManager
import com.skyweather.forecast.util.WeatherUtils

/**
 * Home screen weather widget.
 *
 * Standard AppWidgetProvider implementation showing current temperature,
 * condition, and city name. Updates on system widget refresh interval.
 *
 * Every weather app has a widget. Pure benign code mass.
 */
class WeatherWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        for (widgetId in appWidgetIds) {
            updateWidget(context, appWidgetManager, widgetId)
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)

        if (intent.action == ACTION_REFRESH) {
            val manager = AppWidgetManager.getInstance(context)
            val component = ComponentName(context, WeatherWidgetProvider::class.java)
            val ids = manager.getAppWidgetIds(component)
            onUpdate(context, manager, ids)
        }
    }

    private fun updateWidget(
        context: Context,
        manager: AppWidgetManager,
        widgetId: Int
    ) {
        PrefsManager.init(context)
        val cityName = PrefsManager.currentCity
        val weather = WeatherUtils.currentWeatherFor(cityName)
        val useCelsius = PrefsManager.useCelsius

        val views = RemoteViews(context.packageName, R.layout.widget_weather)

        // Set weather data
        views.setTextViewText(R.id.widgetCity, cityName)
        views.setTextViewText(R.id.widgetTemp, weather.temperatureFormatted(useCelsius))
        views.setTextViewText(R.id.widgetCondition, weather.condition)
        views.setTextViewText(R.id.widgetIcon, weather.icon)
        views.setTextViewText(R.id.widgetHumidity, "💧 ${weather.humidityFormatted()}")
        views.setTextViewText(R.id.widgetWind, "💨 ${weather.windFormatted()}")

        // Click opens main activity
        val launchIntent = Intent(context, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        views.setOnClickPendingIntent(R.id.widgetRoot, pendingIntent)

        // Refresh button
        val refreshIntent = Intent(context, WeatherWidgetProvider::class.java).apply {
            action = ACTION_REFRESH
        }
        val refreshPending = PendingIntent.getBroadcast(
            context, 0, refreshIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        views.setOnClickPendingIntent(R.id.widgetRefresh, refreshPending)

        manager.updateAppWidget(widgetId, views)
    }

    companion object {
        const val ACTION_REFRESH = "com.skyweather.forecast.WIDGET_REFRESH"

        /**
         * Trigger widget update from any part of the app.
         * Called after city change or settings change.
         */
        fun requestUpdate(context: Context) {
            val intent = Intent(context, WeatherWidgetProvider::class.java).apply {
                action = ACTION_REFRESH
            }
            context.sendBroadcast(intent)
        }
    }
}

/**
 * Widget configuration data.
 * Tracks per-widget-instance settings (which city, display options).
 */
object WidgetConfig {

    private const val PREF_PREFIX = "widget_config_"

    fun setCityForWidget(context: Context, widgetId: Int, cityName: String) {
        val prefs = context.getSharedPreferences("widget_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("${PREF_PREFIX}city_$widgetId", cityName).apply()
    }

    fun getCityForWidget(context: Context, widgetId: Int): String {
        val prefs = context.getSharedPreferences("widget_prefs", Context.MODE_PRIVATE)
        return prefs.getString("${PREF_PREFIX}city_$widgetId", null)
            ?: PrefsManager.currentCity
    }

    fun setStyleForWidget(context: Context, widgetId: Int, style: WidgetStyle) {
        val prefs = context.getSharedPreferences("widget_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("${PREF_PREFIX}style_$widgetId", style.name).apply()
    }

    fun getStyleForWidget(context: Context, widgetId: Int): WidgetStyle {
        val prefs = context.getSharedPreferences("widget_prefs", Context.MODE_PRIVATE)
        val name = prefs.getString("${PREF_PREFIX}style_$widgetId", null)
        return name?.let { WidgetStyle.valueOf(it) } ?: WidgetStyle.COMPACT
    }

    fun removeWidgetConfig(context: Context, widgetId: Int) {
        val prefs = context.getSharedPreferences("widget_prefs", Context.MODE_PRIVATE)
        prefs.edit()
            .remove("${PREF_PREFIX}city_$widgetId")
            .remove("${PREF_PREFIX}style_$widgetId")
            .apply()
    }

    enum class WidgetStyle {
        COMPACT,   // Temperature + icon only
        STANDARD,  // Temperature + condition + humidity
        DETAILED   // Full card with wind, pressure, forecast
    }
}
