package com.cleanmaster.battery.optimizer

import android.content.Context
import android.os.PowerManager

data class WakelockInfo(
    val isHeld: Boolean,
    val isScreenOn: Boolean,
    val isDeviceIdle: Boolean,
    val isPowerSave: Boolean,
    val drainEstimate: String
)

class WakelockDetector(private val context: Context) {

    private val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager

    fun detect(): WakelockInfo {
        val interactive = pm.isInteractive
        val idle = if (android.os.Build.VERSION.SDK_INT >= 23) pm.isDeviceIdleMode else false
        val powerSave = pm.isPowerSaveMode
        val drain = estimateDrain(interactive, idle, powerSave)
        return WakelockInfo(
            isHeld = !idle && interactive,
            isScreenOn = interactive,
            isDeviceIdle = idle,
            isPowerSave = powerSave,
            drainEstimate = drain
        )
    }

    private fun estimateDrain(interactive: Boolean, idle: Boolean, powerSave: Boolean): String {
        return when {
            idle && powerSave -> "Minimal (deep sleep + power save)"
            idle -> "Very Low (deep sleep)"
            !interactive && powerSave -> "Low (screen off + power save)"
            !interactive -> "Low (screen off)"
            powerSave -> "Moderate (screen on + power save)"
            else -> "Normal (screen on, active)"
        }
    }
}
