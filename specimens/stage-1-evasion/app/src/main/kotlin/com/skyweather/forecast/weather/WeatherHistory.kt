package com.skyweather.forecast.weather

import java.util.Calendar
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * Historical weather data tracking and trend analysis.
 *
 * Stores temperature, humidity, and pressure readings over time.
 * Provides trend calculations, averages, and comparison to historical norms.
 * Standard feature in weather apps — AccuWeather, Weather Underground, etc.
 */
object WeatherHistory {

    data class HistoricalReading(
        val timestamp: Long,
        val temperature: Double,
        val humidity: Int,
        val pressure: Int,
        val windSpeed: Double,
        val condition: String
    )

    data class DailyStats(
        val date: String,
        val high: Double,
        val low: Double,
        val avgTemp: Double,
        val avgHumidity: Int,
        val avgPressure: Int,
        val dominantCondition: String,
        val totalPrecipMm: Double
    )

    data class TrendReport(
        val period: String,
        val temperatureTrend: String,  // "Rising", "Falling", "Stable"
        val avgTemperature: Double,
        val avgHumidity: Int,
        val tempChangePerDay: Double,
        val warmestDay: DailyStats,
        val coolestDay: DailyStats,
        val rainyDays: Int,
        val clearDays: Int
    )

    // ─── Simulated Historical Data ────────────────────────────────

    /**
     * Generate realistic historical readings for a city over past N hours.
     * Uses sinusoidal temperature model with city-dependent baseline.
     * Real apps store actual sensor/API readings in SQLite.
     */
    fun generateHourlyHistory(cityName: String, hours: Int = 168): List<HistoricalReading> {
        val readings = mutableListOf<HistoricalReading>()
        val now = System.currentTimeMillis()
        val baseSeed = cityName.hashCode().toLong()

        // City-dependent temperature baseline (seasonal adjustment)
        val cal = Calendar.getInstance()
        val dayOfYear = cal.get(Calendar.DAY_OF_YEAR)
        val seasonalOffset = sin(2.0 * Math.PI * dayOfYear / 365.0) * 10.0

        val baseTemp = when {
            cityName.contains("Dubai") || cityName.contains("Cairo") -> 30.0 + seasonalOffset * 0.5
            cityName.contains("Moscow") || cityName.contains("Toronto") -> 5.0 + seasonalOffset * 1.5
            cityName.contains("Sydney") -> 20.0 - seasonalOffset * 0.8 // Southern hemisphere
            cityName.contains("Mumbai") || cityName.contains("Bangkok") -> 28.0 + seasonalOffset * 0.3
            else -> 15.0 + seasonalOffset
        }

        for (h in hours downTo 0) {
            val ts = now - h * 3600_000L
            val pseudo = ((baseSeed + h * 2654435761L) and 0x7FFFFFFF)

            // Diurnal temperature cycle: warmer at 14:00, cooler at 04:00
            val hourOfDay = ((ts / 3600_000L) % 24).toInt()
            val diurnalOffset = sin(2.0 * Math.PI * (hourOfDay - 4) / 24.0) * 5.0

            // Random walk component for day-to-day variation
            val dayVariation = sin(h.toDouble() / 24.0 * 0.3) * 3.0

            val temp = baseTemp + diurnalOffset + dayVariation + (pseudo % 3 - 1)
            val humidity = (50 + diurnalOffset.toInt() * -2 + (pseudo % 20).toInt()).coerceIn(20, 95)
            val pressure = 1010 + (sin(h.toDouble() / 48.0) * 10).toInt() + (pseudo % 5).toInt()
            val wind = 5.0 + (pseudo % 15) + if (humidity > 80) 5.0 else 0.0

            val conditions = if (humidity > 75) {
                listOf("Cloudy", "Rain", "Drizzle", "Overcast")
            } else if (humidity > 50) {
                listOf("Partly Cloudy", "Cloudy", "Clear")
            } else {
                listOf("Clear", "Sunny", "Partly Cloudy")
            }
            val condition = conditions[(pseudo % conditions.size).toInt()]

            readings.add(HistoricalReading(ts, temp, humidity, pressure, wind, condition))
        }

        return readings
    }

    /**
     * Aggregate hourly readings into daily statistics.
     */
    fun dailyStats(readings: List<HistoricalReading>): List<DailyStats> {
        if (readings.isEmpty()) return emptyList()

        // Group by calendar day
        val cal = Calendar.getInstance()
        val grouped = readings.groupBy { reading ->
            cal.timeInMillis = reading.timestamp
            "${cal.get(Calendar.YEAR)}-${cal.get(Calendar.MONTH)}-${cal.get(Calendar.DAY_OF_MONTH)}"
        }

        val months = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

        return grouped.map { (key, dayReadings) ->
            cal.timeInMillis = dayReadings.first().timestamp
            val dateStr = "${months[cal.get(Calendar.MONTH)]} ${cal.get(Calendar.DAY_OF_MONTH)}"

            val temps = dayReadings.map { it.temperature }
            val humidities = dayReadings.map { it.humidity }
            val pressures = dayReadings.map { it.pressure }

            // Dominant condition = most frequent
            val conditionCounts = dayReadings.groupBy { it.condition }
            val dominant = conditionCounts.maxByOrNull { it.value.size }?.key ?: "Clear"

            // Estimate precipitation from rain hours
            val rainHours = dayReadings.count { it.condition in listOf("Rain", "Drizzle") }
            val precipMm = rainHours * 2.5 // rough estimate

            DailyStats(
                date = dateStr,
                high = temps.max(),
                low = temps.min(),
                avgTemp = temps.average(),
                avgHumidity = humidities.average().roundToInt(),
                avgPressure = pressures.average().roundToInt(),
                dominantCondition = dominant,
                totalPrecipMm = precipMm
            )
        }.sortedBy { it.date }
    }

    /**
     * Calculate temperature trend over a period.
     * Linear regression on daily averages.
     */
    fun temperatureTrend(dailyData: List<DailyStats>): TrendReport {
        if (dailyData.isEmpty()) {
            val empty = DailyStats("N/A", 0.0, 0.0, 0.0, 0, 0, "Clear", 0.0)
            return TrendReport("No data", "N/A", 0.0, 0, 0.0, empty, empty, 0, 0)
        }

        val avgTemps = dailyData.map { it.avgTemp }
        val n = avgTemps.size

        // Simple linear regression: temp = a + b * day_index
        val xMean = (n - 1) / 2.0
        val yMean = avgTemps.average()

        var numerator = 0.0
        var denominator = 0.0
        for (i in avgTemps.indices) {
            numerator += (i - xMean) * (avgTemps[i] - yMean)
            denominator += (i - xMean) * (i - xMean)
        }

        val slope = if (denominator != 0.0) numerator / denominator else 0.0

        val trendLabel = when {
            slope > 0.5 -> "Rising"
            slope < -0.5 -> "Falling"
            else -> "Stable"
        }

        val warmest = dailyData.maxBy { it.high }
        val coolest = dailyData.minBy { it.low }
        val rainyDays = dailyData.count { it.dominantCondition in listOf("Rain", "Drizzle") }
        val clearDays = dailyData.count { it.dominantCondition in listOf("Clear", "Sunny") }

        return TrendReport(
            period = "${dailyData.first().date} - ${dailyData.last().date}",
            temperatureTrend = trendLabel,
            avgTemperature = yMean,
            avgHumidity = dailyData.map { it.avgHumidity }.average().roundToInt(),
            tempChangePerDay = slope,
            warmestDay = warmest,
            coolestDay = coolest,
            rainyDays = rainyDays,
            clearDays = clearDays
        )
    }

    /**
     * Compare current temperature to historical average for this date.
     * Returns "Above normal (+3C)", "Near normal", "Below normal (-5C)".
     */
    fun compareToNormal(currentTemp: Double, cityName: String): String {
        // Historical average (simplified — real apps use 30-year climate normals)
        val cal = Calendar.getInstance()
        val dayOfYear = cal.get(Calendar.DAY_OF_YEAR)
        val seasonalAvg = when {
            cityName.contains("Dubai") -> 30.0 + sin(2.0 * Math.PI * dayOfYear / 365.0) * 5.0
            cityName.contains("Moscow") -> 5.0 + sin(2.0 * Math.PI * dayOfYear / 365.0) * 15.0
            cityName.contains("Sydney") -> 20.0 - sin(2.0 * Math.PI * dayOfYear / 365.0) * 8.0
            else -> 15.0 + sin(2.0 * Math.PI * dayOfYear / 365.0) * 10.0
        }

        val diff = currentTemp - seasonalAvg
        return when {
            diff > 3 -> "Above normal (+${diff.roundToInt()}C)"
            diff < -3 -> "Below normal (${diff.roundToInt()}C)"
            else -> "Near normal"
        }
    }

    /**
     * Pressure trend analysis for weather prediction.
     * Falling pressure = approaching low-pressure system = rain likely.
     * Rising pressure = clearing skies.
     */
    fun pressureForecast(readings: List<HistoricalReading>): String {
        if (readings.size < 6) return "Insufficient data"

        val recent = readings.takeLast(6).map { it.pressure }
        val older = readings.takeLast(12).take(6).map { it.pressure }

        val recentAvg = recent.average()
        val olderAvg = older.average()
        val change = recentAvg - olderAvg

        return when {
            change < -5 -> "Rapidly falling pressure - storm approaching"
            change < -2 -> "Falling pressure - rain likely within 12 hours"
            change > 5 -> "Rapidly rising pressure - clearing quickly"
            change > 2 -> "Rising pressure - improving conditions"
            else -> "Steady pressure - conditions continuing"
        }
    }
}
