package com.skyweather.forecast.util

import android.content.Context
import android.graphics.Color
import com.skyweather.forecast.model.WeatherData

/**
 * Dynamic theme engine based on current weather conditions and time of day.
 *
 * Maps weather conditions + time to color palettes, background gradients,
 * and icon sets. Real weather apps (Apple Weather, Google Weather) use
 * dynamic theming extensively.
 *
 * No external dependencies — pure color math and mapping logic.
 */
object ThemeEngine {

    data class WeatherTheme(
        val primaryColor: Int,
        val secondaryColor: Int,
        val backgroundColor: Int,
        val gradientStart: Int,
        val gradientEnd: Int,
        val textColor: Int,
        val accentColor: Int,
        val statusBarColor: Int,
        val iconSet: String,
        val animationType: AnimationType
    )

    enum class AnimationType {
        NONE,
        RAIN_DROPS,
        SNOW_FALL,
        CLOUDS_DRIFT,
        THUNDER_FLASH,
        FOG_DRIFT,
        CLEAR_SPARKLE,
        WIND_LEAVES
    }

    // ─── Condition-Based Themes ──────────────────────────────────

    fun themeForCondition(weather: WeatherData): WeatherTheme {
        val isDaytime = DateUtils.isDaytime()
        val condition = weather.condition.lowercase()

        return when {
            condition.contains("thunder") -> thunderTheme(isDaytime)
            condition.contains("rain") || condition.contains("drizzle") -> rainTheme(isDaytime)
            condition.contains("snow") -> snowTheme(isDaytime)
            condition.contains("fog") || condition.contains("mist") -> fogTheme(isDaytime)
            condition.contains("cloud") || condition.contains("overcast") -> cloudyTheme(isDaytime)
            condition.contains("clear") || condition.contains("sunny") -> clearTheme(isDaytime)
            else -> clearTheme(isDaytime)
        }
    }

    private fun clearTheme(isDaytime: Boolean): WeatherTheme {
        return if (isDaytime) {
            WeatherTheme(
                primaryColor = Color.parseColor("#2196F3"),
                secondaryColor = Color.parseColor("#42A5F5"),
                backgroundColor = Color.parseColor("#E3F2FD"),
                gradientStart = Color.parseColor("#1976D2"),
                gradientEnd = Color.parseColor("#64B5F6"),
                textColor = Color.parseColor("#212121"),
                accentColor = Color.parseColor("#FF9800"),
                statusBarColor = Color.parseColor("#1565C0"),
                iconSet = "day_clear",
                animationType = AnimationType.CLEAR_SPARKLE
            )
        } else {
            WeatherTheme(
                primaryColor = Color.parseColor("#1A237E"),
                secondaryColor = Color.parseColor("#283593"),
                backgroundColor = Color.parseColor("#0D1B2A"),
                gradientStart = Color.parseColor("#0D1B2A"),
                gradientEnd = Color.parseColor("#1B2838"),
                textColor = Color.parseColor("#ECEFF1"),
                accentColor = Color.parseColor("#FFC107"),
                statusBarColor = Color.parseColor("#0A1929"),
                iconSet = "night_clear",
                animationType = AnimationType.NONE
            )
        }
    }

    private fun cloudyTheme(isDaytime: Boolean): WeatherTheme {
        val base = if (isDaytime) Color.parseColor("#78909C") else Color.parseColor("#37474F")
        return WeatherTheme(
            primaryColor = base,
            secondaryColor = Color.parseColor("#90A4AE"),
            backgroundColor = if (isDaytime) Color.parseColor("#ECEFF1") else Color.parseColor("#263238"),
            gradientStart = Color.parseColor("#607D8B"),
            gradientEnd = Color.parseColor("#B0BEC5"),
            textColor = if (isDaytime) Color.parseColor("#212121") else Color.parseColor("#ECEFF1"),
            accentColor = Color.parseColor("#78909C"),
            statusBarColor = Color.parseColor("#546E7A"),
            iconSet = if (isDaytime) "day_cloudy" else "night_cloudy",
            animationType = AnimationType.CLOUDS_DRIFT
        )
    }

    private fun rainTheme(isDaytime: Boolean): WeatherTheme {
        return WeatherTheme(
            primaryColor = Color.parseColor("#455A64"),
            secondaryColor = Color.parseColor("#546E7A"),
            backgroundColor = if (isDaytime) Color.parseColor("#CFD8DC") else Color.parseColor("#1C313A"),
            gradientStart = Color.parseColor("#37474F"),
            gradientEnd = Color.parseColor("#78909C"),
            textColor = if (isDaytime) Color.parseColor("#263238") else Color.parseColor("#CFD8DC"),
            accentColor = Color.parseColor("#4FC3F7"),
            statusBarColor = Color.parseColor("#263238"),
            iconSet = "rain",
            animationType = AnimationType.RAIN_DROPS
        )
    }

    private fun snowTheme(isDaytime: Boolean): WeatherTheme {
        return WeatherTheme(
            primaryColor = Color.parseColor("#90CAF9"),
            secondaryColor = Color.parseColor("#BBDEFB"),
            backgroundColor = if (isDaytime) Color.parseColor("#E8EAF6") else Color.parseColor("#1A237E"),
            gradientStart = Color.parseColor("#C5CAE9"),
            gradientEnd = Color.parseColor("#E8EAF6"),
            textColor = if (isDaytime) Color.parseColor("#1A237E") else Color.parseColor("#E8EAF6"),
            accentColor = Color.parseColor("#82B1FF"),
            statusBarColor = Color.parseColor("#7986CB"),
            iconSet = "snow",
            animationType = AnimationType.SNOW_FALL
        )
    }

    private fun thunderTheme(isDaytime: Boolean): WeatherTheme {
        return WeatherTheme(
            primaryColor = Color.parseColor("#37474F"),
            secondaryColor = Color.parseColor("#263238"),
            backgroundColor = Color.parseColor("#1C1C1C"),
            gradientStart = Color.parseColor("#1A1A2E"),
            gradientEnd = Color.parseColor("#16213E"),
            textColor = Color.parseColor("#ECEFF1"),
            accentColor = Color.parseColor("#FFEB3B"),
            statusBarColor = Color.parseColor("#0F0F23"),
            iconSet = "thunder",
            animationType = AnimationType.THUNDER_FLASH
        )
    }

    private fun fogTheme(isDaytime: Boolean): WeatherTheme {
        return WeatherTheme(
            primaryColor = Color.parseColor("#9E9E9E"),
            secondaryColor = Color.parseColor("#BDBDBD"),
            backgroundColor = if (isDaytime) Color.parseColor("#E0E0E0") else Color.parseColor("#424242"),
            gradientStart = Color.parseColor("#9E9E9E"),
            gradientEnd = Color.parseColor("#E0E0E0"),
            textColor = if (isDaytime) Color.parseColor("#424242") else Color.parseColor("#E0E0E0"),
            accentColor = Color.parseColor("#757575"),
            statusBarColor = Color.parseColor("#757575"),
            iconSet = "fog",
            animationType = AnimationType.FOG_DRIFT
        )
    }

    // ─── Temperature-Based Color ─────────────────────────────────

    /**
     * Map temperature to a color on a cold→hot gradient.
     * Used for temperature bar charts and heatmaps.
     */
    fun temperatureColor(tempC: Double): Int {
        val normalized = ((tempC + 20) / 60.0).coerceIn(0.0, 1.0) // -20C to 40C range

        // Blue → Cyan → Green → Yellow → Orange → Red
        val r: Int
        val g: Int
        val b: Int

        when {
            normalized < 0.2 -> {
                // Blue to cyan
                val t = normalized / 0.2
                r = 0
                g = (128 * t).toInt()
                b = 255
            }
            normalized < 0.4 -> {
                // Cyan to green
                val t = (normalized - 0.2) / 0.2
                r = 0
                g = (128 + 127 * t).toInt()
                b = (255 * (1 - t)).toInt()
            }
            normalized < 0.6 -> {
                // Green to yellow
                val t = (normalized - 0.4) / 0.2
                r = (255 * t).toInt()
                g = 255
                b = 0
            }
            normalized < 0.8 -> {
                // Yellow to orange
                val t = (normalized - 0.6) / 0.2
                r = 255
                g = (255 * (1 - t * 0.5)).toInt()
                b = 0
            }
            else -> {
                // Orange to red
                val t = (normalized - 0.8) / 0.2
                r = 255
                g = (128 * (1 - t)).toInt()
                b = 0
            }
        }

        return Color.rgb(r.coerceIn(0, 255), g.coerceIn(0, 255), b.coerceIn(0, 255))
    }

    /**
     * Generate color for AQI value display.
     */
    fun aqiColor(aqi: Int): Int = when {
        aqi <= 50 -> Color.parseColor("#00E400")   // Good - green
        aqi <= 100 -> Color.parseColor("#FFFF00")  // Moderate - yellow
        aqi <= 150 -> Color.parseColor("#FF7E00")  // USG - orange
        aqi <= 200 -> Color.parseColor("#FF0000")  // Unhealthy - red
        aqi <= 300 -> Color.parseColor("#8F3F97")  // Very unhealthy - purple
        else -> Color.parseColor("#7E0023")         // Hazardous - maroon
    }

    /**
     * Interpolate between two colors.
     * Used for smooth gradient transitions.
     */
    fun interpolateColor(colorA: Int, colorB: Int, fraction: Float): Int {
        val f = fraction.coerceIn(0f, 1f)
        val r = (Color.red(colorA) + (Color.red(colorB) - Color.red(colorA)) * f).toInt()
        val g = (Color.green(colorA) + (Color.green(colorB) - Color.green(colorA)) * f).toInt()
        val b = (Color.blue(colorA) + (Color.blue(colorB) - Color.blue(colorA)) * f).toInt()
        val a = (Color.alpha(colorA) + (Color.alpha(colorB) - Color.alpha(colorA)) * f).toInt()
        return Color.argb(a, r, g, b)
    }
}
