package com.cleanmaster.battery.optimizer.widget

import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager

class BatteryWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        for (widgetId in appWidgetIds) {
            updateWidget(context, appWidgetManager, widgetId)
        }
    }

    override fun onEnabled(context: Context) {
        val prefs = context.getSharedPreferences("widget", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("widget_active", true).apply()
    }

    override fun onDisabled(context: Context) {
        val prefs = context.getSharedPreferences("widget", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("widget_active", false).apply()
    }

    private fun updateWidget(context: Context, manager: AppWidgetManager, widgetId: Int) {
        val batteryInfo = getBatteryInfo(context)
        val prefs = context.getSharedPreferences("widget", Context.MODE_PRIVATE)
        prefs.edit()
            .putInt("last_level_$widgetId", batteryInfo.level)
            .putLong("last_update_$widgetId", System.currentTimeMillis())
            .apply()
    }

    private fun getBatteryInfo(context: Context): BatteryInfo {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val status = context.registerReceiver(null, filter)
        val level = status?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = status?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
        val temp = (status?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) ?: 0) / 10.0
        val voltage = (status?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0) ?: 0) / 1000.0
        val plugged = status?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0
        val health = status?.getIntExtra(BatteryManager.EXTRA_HEALTH, 0) ?: 0
        return BatteryInfo(
            level = (level * 100) / scale,
            temperature = temp,
            voltage = voltage,
            isCharging = plugged != 0,
            chargeType = when (plugged) {
                BatteryManager.BATTERY_PLUGGED_AC -> "AC"
                BatteryManager.BATTERY_PLUGGED_USB -> "USB"
                BatteryManager.BATTERY_PLUGGED_WIRELESS -> "Wireless"
                else -> "None"
            },
            health = when (health) {
                BatteryManager.BATTERY_HEALTH_GOOD -> "Good"
                BatteryManager.BATTERY_HEALTH_OVERHEAT -> "Overheat"
                BatteryManager.BATTERY_HEALTH_DEAD -> "Dead"
                BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "Over Voltage"
                BatteryManager.BATTERY_HEALTH_COLD -> "Cold"
                else -> "Unknown"
            }
        )
    }

    data class BatteryInfo(
        val level: Int,
        val temperature: Double,
        val voltage: Double,
        val isCharging: Boolean,
        val chargeType: String,
        val health: String
    )
}
