package com.cleanmaster.battery.optimizer

import android.content.Context
import android.os.Build

data class ThermalState(
    val cpuTemp: Float,
    val batteryTemp: Float,
    val skinTemp: Float,
    val status: String,
    val throttling: Boolean
)

class ThermalMonitor(private val context: Context) {

    private val cpu = CpuMonitor()
    private val battery = BatteryAnalyzer(context)

    fun getState(): ThermalState {
        val cpuTemp = cpu.getStats().temperature
        val batteryTemp = battery.analyze().temperature
        val skinTemp = estimateSkinTemp(cpuTemp, batteryTemp)
        val throttling = cpuTemp > 45 || batteryTemp > 42
        val status = when {
            cpuTemp > 50 -> "Critical"
            cpuTemp > 45 -> "Hot"
            cpuTemp > 38 -> "Warm"
            else -> "Normal"
        }
        return ThermalState(cpuTemp, batteryTemp, skinTemp, status, throttling)
    }

    private fun estimateSkinTemp(cpu: Float, battery: Float): Float {
        return (cpu * 0.4f + battery * 0.6f)
    }

    fun getCoolDownTips(): List<String> {
        val state = getState()
        val tips = mutableListOf<String>()
        if (state.cpuTemp > 45) tips.add("Close heavy apps to reduce CPU temperature")
        if (state.batteryTemp > 40) tips.add("Unplug charger and let device cool down")
        if (state.throttling) tips.add("Performance throttled — reduce workload")
        if (tips.isEmpty()) tips.add("Temperature is normal")
        return tips
    }

    fun supportsThermalApi(): Boolean = Build.VERSION.SDK_INT >= 29
}
