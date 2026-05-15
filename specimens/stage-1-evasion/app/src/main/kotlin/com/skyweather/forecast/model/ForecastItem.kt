package com.skyweather.forecast.model

/**
 * Single day in a multi-day forecast.
 */
data class ForecastItem(
    val dayOfWeek: String,
    val high: Double,
    val low: Double,
    val condition: String,
    val icon: String,
    val precipChance: Int,
    val humidity: Int,
    val windSpeed: Double
) {
    fun highFormatted(useCelsius: Boolean): String {
        val temp = if (useCelsius) high else high * 9.0 / 5.0 + 32.0
        return "${temp.toInt()}°"
    }

    fun lowFormatted(useCelsius: Boolean): String {
        val temp = if (useCelsius) low else low * 9.0 / 5.0 + 32.0
        return "${temp.toInt()}°"
    }

    fun precipFormatted(): String = "$precipChance%"
}
