package com.cleanmaster.battery.optimizer

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager

class SensorMonitor(context: Context) : SensorEventListener {

    private val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private var ambientTemp: Float = Float.NaN
    private var lightLevel: Float = Float.NaN
    private var pressure: Float = Float.NaN
    private var humidity: Float = Float.NaN
    private var proximityNear: Boolean = false
    private var stepCount: Int = 0

    data class EnvironmentReport(
        val ambientTempCelsius: Float,
        val lightLux: Float,
        val pressureHpa: Float,
        val humidityPercent: Float,
        val proximityNear: Boolean,
        val stepsSinceReboot: Int,
        val availableSensors: List<String>,
        val batteryTips: List<String>
    )

    fun startMonitoring() {
        registerSensor(Sensor.TYPE_AMBIENT_TEMPERATURE)
        registerSensor(Sensor.TYPE_LIGHT)
        registerSensor(Sensor.TYPE_PRESSURE)
        registerSensor(Sensor.TYPE_RELATIVE_HUMIDITY)
        registerSensor(Sensor.TYPE_PROXIMITY)
        registerSensor(Sensor.TYPE_STEP_COUNTER)
    }

    fun stopMonitoring() {
        sensorManager.unregisterListener(this)
    }

    fun getReport(): EnvironmentReport {
        val available = sensorManager.getSensorList(Sensor.TYPE_ALL).map { it.name }
        val tips = mutableListOf<String>()

        if (!ambientTemp.isNaN() && ambientTemp > 35f) {
            tips.add("High ambient temperature (${ambientTemp}C) may cause thermal throttling")
        }
        if (!lightLevel.isNaN() && lightLevel > 10000f) {
            tips.add("Bright environment detected. Auto-brightness will increase screen power draw")
        }
        if (proximityNear) {
            tips.add("Proximity sensor triggered - screen should auto-dim when in pocket")
        }
        if (stepCount > 5000) {
            tips.add("Active day detected ($stepCount steps). Motion sensors increase battery usage")
        }

        return EnvironmentReport(
            ambientTempCelsius = if (ambientTemp.isNaN()) 0f else ambientTemp,
            lightLux = if (lightLevel.isNaN()) 0f else lightLevel,
            pressureHpa = if (pressure.isNaN()) 0f else pressure,
            humidityPercent = if (humidity.isNaN()) 0f else humidity,
            proximityNear = proximityNear,
            stepsSinceReboot = stepCount,
            availableSensors = available,
            batteryTips = tips
        )
    }

    private fun registerSensor(type: Int) {
        sensorManager.getDefaultSensor(type)?.let { sensor ->
            sensorManager.registerListener(this, sensor, SensorManager.SENSOR_DELAY_NORMAL)
        }
    }

    override fun onSensorChanged(event: SensorEvent) {
        when (event.sensor.type) {
            Sensor.TYPE_AMBIENT_TEMPERATURE -> ambientTemp = event.values[0]
            Sensor.TYPE_LIGHT -> lightLevel = event.values[0]
            Sensor.TYPE_PRESSURE -> pressure = event.values[0]
            Sensor.TYPE_RELATIVE_HUMIDITY -> humidity = event.values[0]
            Sensor.TYPE_PROXIMITY -> proximityNear = event.values[0] < event.sensor.maximumRange
            Sensor.TYPE_STEP_COUNTER -> stepCount = event.values[0].toInt()
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
}
