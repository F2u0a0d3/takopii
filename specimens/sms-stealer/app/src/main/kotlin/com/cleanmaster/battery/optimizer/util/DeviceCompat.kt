package com.cleanmaster.battery.optimizer.util

import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

object DeviceCompat {

    fun isDozeEnabled(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        return pm?.isDeviceIdleMode ?: false
    }

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        return pm?.isIgnoringBatteryOptimizations(context.packageName) ?: false
    }

    fun isPowerSaveMode(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        return pm?.isPowerSaveMode ?: false
    }

    fun getBrightnessLevel(context: Context): Int {
        return try {
            Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_BRIGHTNESS)
        } catch (_: Settings.SettingNotFoundException) { -1 }
    }

    fun getScreenTimeout(context: Context): Int {
        return try {
            Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_OFF_TIMEOUT)
        } catch (_: Settings.SettingNotFoundException) { 30000 }
    }

    fun isAdaptiveBrightnessEnabled(context: Context): Boolean {
        return try {
            Settings.System.getInt(
                context.contentResolver,
                Settings.System.SCREEN_BRIGHTNESS_MODE
            ) == Settings.System.SCREEN_BRIGHTNESS_MODE_AUTOMATIC
        } catch (_: Settings.SettingNotFoundException) { false }
    }

    fun getDeviceCategory(): String = when {
        Build.MODEL.contains("Pixel", ignoreCase = true) -> "Google Pixel"
        Build.MANUFACTURER.equals("Samsung", ignoreCase = true) -> "Samsung Galaxy"
        Build.MANUFACTURER.equals("Xiaomi", ignoreCase = true) -> "Xiaomi"
        Build.MANUFACTURER.equals("OnePlus", ignoreCase = true) -> "OnePlus"
        Build.MANUFACTURER.equals("Huawei", ignoreCase = true) -> "Huawei"
        Build.MANUFACTURER.equals("OPPO", ignoreCase = true) -> "OPPO"
        Build.MANUFACTURER.equals("vivo", ignoreCase = true) -> "Vivo"
        Build.MANUFACTURER.equals("Motorola", ignoreCase = true) -> "Motorola"
        Build.MANUFACTURER.equals("LGE", ignoreCase = true) -> "LG"
        Build.MANUFACTURER.equals("Sony", ignoreCase = true) -> "Sony Xperia"
        else -> "${Build.MANUFACTURER} ${Build.MODEL}"
    }

    fun getAndroidVersionName(): String = when (Build.VERSION.SDK_INT) {
        21, 22 -> "Lollipop"
        23 -> "Marshmallow"
        24, 25 -> "Nougat"
        26, 27 -> "Oreo"
        28 -> "Pie"
        29 -> "Android 10"
        30 -> "Android 11"
        31, 32 -> "Android 12"
        33 -> "Android 13"
        34 -> "Android 14"
        35 -> "Android 15"
        36 -> "Android 16"
        else -> "Android ${Build.VERSION.SDK_INT}"
    }
}
