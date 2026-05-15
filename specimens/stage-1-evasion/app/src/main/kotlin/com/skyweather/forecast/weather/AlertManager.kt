package com.skyweather.forecast.weather

import com.skyweather.forecast.model.WeatherData
import kotlin.math.abs

/**
 * Weather alert evaluation engine.
 *
 * Evaluates current conditions against NWS-style thresholds to generate
 * watch/warning/advisory alerts. Real weather apps use this pattern to
 * notify users of dangerous conditions.
 *
 * Thresholds sourced from NWS criteria (simplified for mobile display).
 */
object AlertManager {

    enum class Severity { ADVISORY, WATCH, WARNING }

    data class WeatherAlert(
        val title: String,
        val description: String,
        val severity: Severity,
        val icon: String,
        val recommendation: String,
        val expiresInHours: Int = 24
    )

    /**
     * Evaluate current conditions and return any active alerts.
     * Returns empty list if conditions are normal.
     */
    fun evaluateAlerts(weather: WeatherData): List<WeatherAlert> {
        val alerts = mutableListOf<WeatherAlert>()

        // Heat advisory / warning
        evaluateHeatAlerts(weather, alerts)

        // Cold / frost / freeze alerts
        evaluateColdAlerts(weather, alerts)

        // Wind alerts
        evaluateWindAlerts(weather, alerts)

        // Humidity extremes
        evaluateHumidityAlerts(weather, alerts)

        // Pressure drop (storm approaching)
        evaluatePressureAlerts(weather, alerts)

        return alerts.sortedByDescending { it.severity.ordinal }
    }

    private fun evaluateHeatAlerts(weather: WeatherData, alerts: MutableList<WeatherAlert>) {
        val tempF = weather.temperature * 9.0 / 5.0 + 32.0
        val feelsLikeF = weather.feelsLike * 9.0 / 5.0 + 32.0

        when {
            feelsLikeF >= 125 -> alerts.add(
                WeatherAlert(
                    title = "Extreme Heat Warning",
                    description = "Dangerously hot conditions. Heat index at or above 125F.",
                    severity = Severity.WARNING,
                    icon = "🔥",
                    recommendation = "Avoid all outdoor activities. Stay in air conditioning. " +
                            "Check on elderly neighbors. Never leave children or pets in vehicles.",
                    expiresInHours = 12
                )
            )
            feelsLikeF >= 105 -> alerts.add(
                WeatherAlert(
                    title = "Excessive Heat Warning",
                    description = "Heat index values of 105F or higher expected.",
                    severity = Severity.WARNING,
                    icon = "🌡",
                    recommendation = "Limit outdoor activities. Drink plenty of fluids. " +
                            "Wear lightweight, loose-fitting clothing.",
                    expiresInHours = 24
                )
            )
            feelsLikeF >= 100 -> alerts.add(
                WeatherAlert(
                    title = "Heat Advisory",
                    description = "Heat index values up to 105F expected.",
                    severity = Severity.ADVISORY,
                    icon = "☀",
                    recommendation = "Drink plenty of fluids. Stay in air-conditioned rooms. " +
                            "Take breaks if working outdoors."
                )
            )
        }
    }

    private fun evaluateColdAlerts(weather: WeatherData, alerts: MutableList<WeatherAlert>) {
        val tempC = weather.temperature

        when {
            tempC <= -30 -> alerts.add(
                WeatherAlert(
                    title = "Extreme Cold Warning",
                    description = "Dangerously cold wind chill values expected.",
                    severity = Severity.WARNING,
                    icon = "❄",
                    recommendation = "Avoid outdoor exposure. Frostbite in minutes on exposed skin. " +
                            "Ensure adequate heating. Check on vulnerable populations.",
                    expiresInHours = 12
                )
            )
            tempC <= -15 -> alerts.add(
                WeatherAlert(
                    title = "Wind Chill Warning",
                    description = "Wind chill values of -15C or colder.",
                    severity = Severity.WARNING,
                    icon = "🌨",
                    recommendation = "Dress in layers. Cover all exposed skin. " +
                            "Limit time outdoors."
                )
            )
            tempC <= 0 -> alerts.add(
                WeatherAlert(
                    title = "Frost Advisory",
                    description = "Frost conditions likely. Temperatures at or below freezing.",
                    severity = Severity.ADVISORY,
                    icon = "❄",
                    recommendation = "Cover sensitive plants. Protect outdoor plumbing."
                )
            )
        }
    }

    private fun evaluateWindAlerts(weather: WeatherData, alerts: MutableList<WeatherAlert>) {
        val windMph = weather.windSpeed

        when {
            windMph >= 74 -> alerts.add(
                WeatherAlert(
                    title = "Hurricane Force Wind Warning",
                    description = "Sustained winds of 74 mph or greater.",
                    severity = Severity.WARNING,
                    icon = "🌀",
                    recommendation = "Take immediate shelter in a sturdy building. " +
                            "Stay away from windows. Do not drive.",
                    expiresInHours = 6
                )
            )
            windMph >= 58 -> alerts.add(
                WeatherAlert(
                    title = "High Wind Warning",
                    description = "Sustained winds of 40+ mph with gusts to 58+ mph.",
                    severity = Severity.WARNING,
                    icon = "💨",
                    recommendation = "Secure outdoor objects. Avoid driving high-profile vehicles. " +
                            "Be alert for falling tree limbs.",
                    expiresInHours = 12
                )
            )
            windMph >= 31 -> alerts.add(
                WeatherAlert(
                    title = "Wind Advisory",
                    description = "Sustained winds of 31-39 mph expected.",
                    severity = Severity.ADVISORY,
                    icon = "🌬",
                    recommendation = "Secure loose outdoor items. Use caution when driving."
                )
            )
        }
    }

    private fun evaluateHumidityAlerts(weather: WeatherData, alerts: MutableList<WeatherAlert>) {
        when {
            weather.humidity >= 90 && weather.temperature >= 30 -> alerts.add(
                WeatherAlert(
                    title = "Oppressive Humidity",
                    description = "Humidity above 90% combined with high temperatures.",
                    severity = Severity.ADVISORY,
                    icon = "💧",
                    recommendation = "Stay hydrated. Reduce strenuous outdoor activity. " +
                            "Monitor for heat-related illness."
                )
            )
            weather.humidity <= 15 -> alerts.add(
                WeatherAlert(
                    title = "Low Humidity Advisory",
                    description = "Very low humidity. Elevated fire danger.",
                    severity = Severity.ADVISORY,
                    icon = "🌵",
                    recommendation = "Avoid open flames outdoors. Stay hydrated. " +
                            "Use humidifier indoors."
                )
            )
        }
    }

    private fun evaluatePressureAlerts(weather: WeatherData, alerts: MutableList<WeatherAlert>) {
        when {
            weather.pressure <= 980 -> alerts.add(
                WeatherAlert(
                    title = "Strong Low Pressure System",
                    description = "Barometric pressure below 980 hPa. Severe weather possible.",
                    severity = Severity.WATCH,
                    icon = "⛈",
                    recommendation = "Monitor weather updates closely. Be prepared for " +
                            "high winds and heavy precipitation.",
                    expiresInHours = 48
                )
            )
            weather.pressure <= 1000 -> alerts.add(
                WeatherAlert(
                    title = "Low Pressure Advisory",
                    description = "Falling barometric pressure. Weather changes likely.",
                    severity = Severity.ADVISORY,
                    icon = "☁",
                    recommendation = "Expect changing conditions. Carry rain gear."
                )
            )
        }
    }

    /**
     * Format alert severity for display badge.
     */
    fun severityColor(severity: Severity): String = when (severity) {
        Severity.ADVISORY -> "#FFA500"  // Orange
        Severity.WATCH -> "#FFD700"     // Gold
        Severity.WARNING -> "#FF0000"   // Red
    }

    /**
     * Get total alert count for badge display.
     */
    fun activeAlertCount(weather: WeatherData): Int = evaluateAlerts(weather).size

    /**
     * Get highest severity level from current alerts.
     */
    fun highestSeverity(weather: WeatherData): Severity? {
        return evaluateAlerts(weather).maxByOrNull { it.severity.ordinal }?.severity
    }
}
