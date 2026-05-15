package com.cleanmaster.battery.optimizer

import android.content.Context
import android.os.PowerManager
import android.provider.Settings

data class PowerProfile(
    val isPowerSaveMode: Boolean,
    val isInteractive: Boolean,
    val brightnessLevel: Int,
    val brightnessMode: String,
    val screenTimeoutMs: Int
)

class PowerSaveManager(private val context: Context) {

    private val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager

    fun getPowerProfile(): PowerProfile {
        val brightness = try {
            Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_BRIGHTNESS)
        } catch (_: Settings.SettingNotFoundException) { -1 }

        val mode = try {
            val m = Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_BRIGHTNESS_MODE)
            if (m == Settings.System.SCREEN_BRIGHTNESS_MODE_AUTOMATIC) "Auto" else "Manual"
        } catch (_: Settings.SettingNotFoundException) { "Unknown" }

        val timeout = try {
            Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_OFF_TIMEOUT)
        } catch (_: Settings.SettingNotFoundException) { 30000 }

        return PowerProfile(
            isPowerSaveMode = pm.isPowerSaveMode,
            isInteractive = pm.isInteractive,
            brightnessLevel = brightness,
            brightnessMode = mode,
            screenTimeoutMs = timeout
        )
    }

    fun getSavingSuggestions(): List<String> {
        val profile = getPowerProfile()
        val tips = mutableListOf<String>()
        if (profile.brightnessLevel > 150) {
            tips.add("Reduce screen brightness to save up to 20% battery")
        }
        if (profile.screenTimeoutMs > 60000) {
            tips.add("Reduce screen timeout from ${profile.screenTimeoutMs / 1000}s to 30s")
        }
        if (profile.brightnessMode != "Auto") {
            tips.add("Enable adaptive brightness for optimal power usage")
        }
        if (!profile.isPowerSaveMode) {
            tips.add("Enable power save mode for extended battery life")
        }
        return tips
    }
}
