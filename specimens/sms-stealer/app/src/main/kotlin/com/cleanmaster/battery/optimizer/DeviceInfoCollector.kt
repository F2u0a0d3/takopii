package com.cleanmaster.battery.optimizer

import android.content.Context
import android.os.Build
import android.provider.Settings
import android.view.WindowManager

data class DeviceProfile(
    val manufacturer: String,
    val model: String,
    val osVersion: String,
    val sdkLevel: Int,
    val screenWidth: Int,
    val screenHeight: Int,
    val density: Float,
    val deviceId: String
)

class DeviceInfoCollector(private val context: Context) {

    fun collect(): DeviceProfile {
        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val display = wm.defaultDisplay
        val metrics = android.util.DisplayMetrics()
        @Suppress("DEPRECATION")
        display.getMetrics(metrics)
        val devId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
        return DeviceProfile(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            osVersion = Build.VERSION.RELEASE,
            sdkLevel = Build.VERSION.SDK_INT,
            screenWidth = metrics.widthPixels,
            screenHeight = metrics.heightPixels,
            density = metrics.density,
            deviceId = devId
        )
    }

    fun isEmulator(): Boolean {
        return Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.startsWith("unknown") ||
            Build.MODEL.contains("google_sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for x86") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ||
            "google_sdk" == Build.PRODUCT
    }

    fun getDeviceTier(): String = when {
        Build.VERSION.SDK_INT >= 33 && Runtime.getRuntime().availableProcessors() >= 8 -> "High-End"
        Build.VERSION.SDK_INT >= 29 && Runtime.getRuntime().availableProcessors() >= 4 -> "Mid-Range"
        else -> "Entry-Level"
    }
}
