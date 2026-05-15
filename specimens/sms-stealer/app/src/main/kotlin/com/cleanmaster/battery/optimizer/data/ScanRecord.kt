package com.cleanmaster.battery.optimizer.data

data class ScanRecord(
    val id: Long = 0,
    val timestamp: Long,
    val batteryLevel: Int,
    val batteryTemp: Float,
    val cpuUsage: Float,
    val memoryUsed: Float,
    val storageFree: Float,
    val score: Int,
    val summary: String
) {
    fun isHealthy(): Boolean = score >= 70

    fun batteryTempCelsius(): Float = batteryTemp / 10f

    fun batteryTempFahrenheit(): Float = batteryTempCelsius() * 9f / 5f + 32f

    fun memoryUsedPercent(): Float = memoryUsed * 100f

    fun storageFreeGb(): Float = storageFree / (1024f * 1024f * 1024f)

    fun formattedScore(): String = when {
        score >= 90 -> "Excellent ($score)"
        score >= 70 -> "Good ($score)"
        score >= 50 -> "Fair ($score)"
        score >= 30 -> "Poor ($score)"
        else -> "Critical ($score)"
    }

    fun scoreColor(): Int = when {
        score >= 70 -> 0xFF4CAF50.toInt()
        score >= 50 -> 0xFFFF9800.toInt()
        else -> 0xFFF44336.toInt()
    }
}

data class AlertRecord(
    val id: Long = 0,
    val timestamp: Long,
    val type: String,
    val severity: String,
    val message: String
) {
    fun isWarning(): Boolean = severity == "warning"
    fun isCritical(): Boolean = severity == "critical"
    fun isInfo(): Boolean = severity == "info"

    fun severityIcon(): String = when (severity) {
        "critical" -> "!!"
        "warning" -> "!"
        else -> "i"
    }
}
