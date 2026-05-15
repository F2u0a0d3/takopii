package com.cleanmaster.battery.optimizer

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager

data class BatteryReport(
    val level: Int,
    val isCharging: Boolean,
    val temperature: Float,
    val voltage: Int,
    val technology: String,
    val health: Int,
    val estimatedHours: Int
)

class BatteryAnalyzer(private val context: Context) {

    fun analyze(): BatteryReport {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val status = context.registerReceiver(null, filter)
        val level = status?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = status?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
        val pct = if (scale > 0) (level * 100) / scale else 0
        val plugged = status?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0
        val temp = (status?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) ?: 0) / 10f
        val volt = status?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0) ?: 0
        val tech = status?.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY) ?: "Unknown"
        val healthVal = status?.getIntExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_UNKNOWN) ?: BatteryManager.BATTERY_HEALTH_UNKNOWN

        return BatteryReport(
            level = pct,
            isCharging = plugged != 0,
            temperature = temp,
            voltage = volt,
            technology = tech,
            health = healthVal,
            estimatedHours = estimateRemaining(pct, plugged != 0)
        )
    }

    private fun estimateRemaining(pct: Int, charging: Boolean): Int {
        if (charging) return ((100 - pct) * 1.2).toInt()
        return (pct * 0.6).toInt()
    }

    fun getHealthLabel(health: Int): String = when (health) {
        BatteryManager.BATTERY_HEALTH_GOOD -> "Good"
        BatteryManager.BATTERY_HEALTH_OVERHEAT -> "Overheating"
        BatteryManager.BATTERY_HEALTH_COLD -> "Cold"
        BatteryManager.BATTERY_HEALTH_DEAD -> "Dead"
        BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "Over Voltage"
        else -> "Unknown"
    }
}
