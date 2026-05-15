package com.skyweather.forecast.util

import com.skyweather.forecast.model.ForecastItem
import com.skyweather.forecast.model.WeatherData
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sqrt

/**
 * Weather calculation utilities — real meteorological formulas.
 * Adds substantial benign code mass with legitimate computational logic.
 * (Takopii Stage 2: benign code mass dilution)
 */
object WeatherUtils {

    /** Wind chill calculation (NWS formula) */
    fun windChill(tempF: Double, windMph: Double): Double {
        if (tempF > 50.0 || windMph < 3.0) return tempF
        return 35.74 + 0.6215 * tempF - 35.75 * windMph.pow(0.16) +
                0.4275 * tempF * windMph.pow(0.16)
    }

    /** Heat index calculation (Rothfusz regression) */
    fun heatIndex(tempF: Double, humidity: Int): Double {
        if (tempF < 80.0) return tempF
        val rh = humidity.toDouble()
        var hi = -42.379 + 2.04901523 * tempF + 10.14333127 * rh -
                0.22475541 * tempF * rh - 0.00683783 * tempF * tempF -
                0.05481717 * rh * rh + 0.00122874 * tempF * tempF * rh +
                0.00085282 * tempF * rh * rh - 0.00000199 * tempF * tempF * rh * rh

        if (rh < 13.0 && tempF in 80.0..112.0) {
            hi -= ((13.0 - rh) / 4.0) * sqrt((17.0 - (tempF - 95.0).let { if (it < 0) -it else it }) / 17.0)
        }
        if (rh > 85.0 && tempF in 80.0..87.0) {
            hi += ((rh - 85.0) / 10.0) * ((87.0 - tempF) / 5.0)
        }
        return hi
    }

    /** Dew point approximation (Magnus formula) */
    fun dewPoint(tempC: Double, humidity: Int): Double {
        val a = 17.27
        val b = 237.7
        val rh = humidity.toDouble() / 100.0
        val alpha = (a * tempC) / (b + tempC) + kotlin.math.ln(rh)
        return (b * alpha) / (a - alpha)
    }

    /** UV index description */
    fun uvDescription(index: Int): String = when {
        index <= 2 -> "Low"
        index <= 5 -> "Moderate"
        index <= 7 -> "High"
        index <= 10 -> "Very High"
        else -> "Extreme"
    }

    /** Beaufort wind scale */
    fun beaufortScale(windMph: Double): String = when {
        windMph < 1 -> "Calm"
        windMph < 4 -> "Light Air"
        windMph < 8 -> "Light Breeze"
        windMph < 13 -> "Gentle Breeze"
        windMph < 19 -> "Moderate Breeze"
        windMph < 25 -> "Fresh Breeze"
        windMph < 32 -> "Strong Breeze"
        windMph < 39 -> "Near Gale"
        windMph < 47 -> "Gale"
        windMph < 55 -> "Strong Gale"
        windMph < 64 -> "Storm"
        windMph < 73 -> "Violent Storm"
        else -> "Hurricane"
    }

    /** Visibility category */
    fun visibilityCategory(km: Double): String = when {
        km < 1 -> "Very Poor"
        km < 4 -> "Poor"
        km < 10 -> "Moderate"
        km < 20 -> "Good"
        else -> "Excellent"
    }

    /** Comfort level based on temperature + humidity */
    fun comfortLevel(tempC: Double, humidity: Int): String {
        val hi = heatIndex(tempC * 9.0 / 5.0 + 32.0, humidity)
        return when {
            hi < 60 -> "Cold"
            hi < 75 -> "Comfortable"
            hi < 85 -> "Warm"
            hi < 95 -> "Hot"
            else -> "Dangerous"
        }
    }

    /** Weather condition to emoji icon */
    fun conditionIcon(condition: String): String = when (condition.lowercase()) {
        "clear", "sunny" -> "☀️"
        "partly cloudy" -> "⛅"
        "cloudy", "overcast" -> "☁️"
        "rain", "rainy", "drizzle" -> "🌧️"
        "thunderstorm" -> "⛈️"
        "snow", "snowy" -> "❄️"
        "fog", "mist" -> "🌫️"
        "windy" -> "🌬️"
        else -> "☀️"
    }

    /**
     * Generate hardcoded but realistic weather data for cities.
     * This is the "API response" — no actual network call needed.
     * Design constraint: benign code that works without network reduces suspicion.
     */
    fun currentWeatherFor(cityName: String): WeatherData {
        // Deterministic "random" based on city name hash + day
        val seed = cityName.hashCode().toLong() + (System.currentTimeMillis() / 86400000)
        val pseudo = ((seed * 1103515245 + 12345) and 0x7FFFFFFF)

        val baseTemp = when {
            cityName.contains("Dubai") || cityName.contains("Cairo") -> 35.0
            cityName.contains("Moscow") || cityName.contains("Toronto") -> 5.0
            cityName.contains("Sydney") -> 22.0
            cityName.contains("Mumbai") || cityName.contains("Bangkok") -> 32.0
            else -> 18.0
        }

        val temp = baseTemp + (pseudo % 10) - 5
        val humidity = 40 + (pseudo % 50).toInt()
        val wind = 3.0 + (pseudo % 20)
        val conditions = listOf("Clear", "Partly Cloudy", "Cloudy", "Rain", "Sunny")
        val condition = conditions[(pseudo % conditions.size).toInt()]

        return WeatherData(
            city = cityName,
            country = "",
            temperature = temp.toDouble(),
            feelsLike = temp + (if (humidity > 70) 3.0 else -2.0),
            humidity = humidity,
            windSpeed = wind.toDouble(),
            windDirection = listOf("N", "NE", "E", "SE", "S", "SW", "W", "NW")[(pseudo % 8).toInt()],
            pressure = 1000 + (pseudo % 30).toInt(),
            condition = condition,
            icon = conditionIcon(condition)
        )
    }

    /** Generate 5-day forecast for a city */
    fun forecastFor(cityName: String): List<ForecastItem> {
        val days = listOf("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        val today = ((System.currentTimeMillis() / 86400000) % 7).toInt()

        return (1..5).map { offset ->
            val dayIndex = (today + offset) % 7
            val seed = (cityName.hashCode().toLong() + offset * 7919) and 0x7FFFFFFF
            val pseudo = ((seed * 1103515245 + 12345) and 0x7FFFFFFF)

            val baseHigh = currentWeatherFor(cityName).temperature + (pseudo % 5) - 2
            val conditions = listOf("Clear", "Partly Cloudy", "Cloudy", "Rain", "Sunny", "Drizzle")
            val condition = conditions[(pseudo % conditions.size).toInt()]

            ForecastItem(
                dayOfWeek = days[dayIndex],
                high = baseHigh,
                low = baseHigh - 5.0 - (pseudo % 8),
                condition = condition,
                icon = conditionIcon(condition),
                precipChance = (pseudo % 80).toInt(),
                humidity = 35 + (pseudo % 55).toInt(),
                windSpeed = 2.0 + (pseudo % 25)
            )
        }
    }
}
