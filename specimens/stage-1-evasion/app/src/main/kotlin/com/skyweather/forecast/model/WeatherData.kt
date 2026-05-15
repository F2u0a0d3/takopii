package com.skyweather.forecast.model

/**
 * Current weather conditions for a city.
 * Benign model class — real weather app data structure.
 */
data class WeatherData(
    val city: String,
    val country: String,
    val temperature: Double,
    val feelsLike: Double,
    val humidity: Int,
    val windSpeed: Double,
    val windDirection: String,
    val pressure: Int,
    val condition: String,
    val icon: String,
    val timestamp: Long = System.currentTimeMillis()
) {
    fun temperatureFormatted(useCelsius: Boolean): String {
        val temp = if (useCelsius) temperature else celsiusToFahrenheit(temperature)
        return "${temp.toInt()}°${if (useCelsius) "C" else "F"}"
    }

    fun feelsLikeFormatted(useCelsius: Boolean): String {
        val temp = if (useCelsius) feelsLike else celsiusToFahrenheit(feelsLike)
        return "Feels like ${temp.toInt()}°"
    }

    fun windFormatted(): String = "${windSpeed.toInt()} mph $windDirection"

    fun pressureFormatted(): String = "$pressure hPa"

    fun humidityFormatted(): String = "$humidity%"

    private fun celsiusToFahrenheit(c: Double): Double = c * 9.0 / 5.0 + 32.0
}
