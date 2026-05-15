package com.skyweather.forecast.weather

import java.util.Calendar
import java.util.TimeZone
import kotlin.math.PI
import kotlin.math.acos
import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.tan

/**
 * Solar position and sunrise/sunset calculator.
 *
 * Implements NOAA simplified solar equations for:
 *   - Sunrise / sunset times
 *   - Solar noon
 *   - Day length
 *   - Golden hour / blue hour windows
 *   - UV index estimation based on solar angle
 *
 * Reference: NOAA Solar Calculator (https://gml.noaa.gov/grad/solcalc/)
 */
object SunCalculator {

    data class SolarDay(
        val sunrise: String,
        val sunset: String,
        val solarNoon: String,
        val dayLength: String,
        val goldenHourMorning: String,
        val goldenHourEvening: String,
        val blueHourMorning: String,
        val blueHourEvening: String,
        val currentSolarElevation: Double,
        val estimatedUvIndex: Int
    )

    /**
     * Calculate solar day information for given coordinates.
     *
     * @param lat Latitude in decimal degrees (positive = north)
     * @param lon Longitude in decimal degrees (positive = east)
     * @param tzOffsetHours Timezone offset from UTC
     */
    fun calculate(lat: Double, lon: Double, tzOffsetHours: Int): SolarDay {
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        val year = cal.get(Calendar.YEAR)
        val month = cal.get(Calendar.MONTH) + 1
        val day = cal.get(Calendar.DAY_OF_MONTH)
        val hour = cal.get(Calendar.HOUR_OF_DAY)
        val minute = cal.get(Calendar.MINUTE)

        // Julian day number
        val jd = julianDay(year, month, day)

        // Julian century
        val jc = (jd - 2451545.0) / 36525.0

        // Solar geometry
        val meanLon = (280.46646 + jc * (36000.76983 + 0.0003032 * jc)) % 360
        val meanAnomaly = 357.52911 + jc * (35999.05029 - 0.0001537 * jc)
        val eccentricity = 0.016708634 - jc * (0.000042037 + 0.0000001267 * jc)

        val sinMa = sin(Math.toRadians(meanAnomaly))
        val sin2Ma = sin(Math.toRadians(2 * meanAnomaly))
        val sin3Ma = sin(Math.toRadians(3 * meanAnomaly))

        val equationOfCenter = sinMa * (1.914602 - jc * (0.004817 + 0.000014 * jc)) +
                sin2Ma * (0.019993 - 0.000101 * jc) + sin3Ma * 0.000289

        val sunTrueLon = meanLon + equationOfCenter
        val sunAppLon = sunTrueLon - 0.00569 - 0.00478 * sin(Math.toRadians(125.04 - 1934.136 * jc))

        // Obliquity of ecliptic
        val meanObliquity = 23.0 + (26.0 + (21.448 - jc * (46.815 + jc * (0.00059 - jc * 0.001813))) / 60.0) / 60.0
        val obliquityCorr = meanObliquity + 0.00256 * cos(Math.toRadians(125.04 - 1934.136 * jc))

        // Solar declination
        val declination = Math.toDegrees(
            asin(sin(Math.toRadians(obliquityCorr)) * sin(Math.toRadians(sunAppLon)))
        )

        // Equation of time (minutes)
        val y = tan(Math.toRadians(obliquityCorr / 2)) * tan(Math.toRadians(obliquityCorr / 2))
        val eqTime = 4 * Math.toDegrees(
            y * sin(2 * Math.toRadians(meanLon)) -
                    2 * eccentricity * sin(Math.toRadians(meanAnomaly)) +
                    4 * eccentricity * y * sin(Math.toRadians(meanAnomaly)) * cos(2 * Math.toRadians(meanLon)) -
                    0.5 * y * y * sin(4 * Math.toRadians(meanLon)) -
                    1.25 * eccentricity * eccentricity * sin(2 * Math.toRadians(meanAnomaly))
        )

        // Hour angle for sunrise/sunset (standard refraction -0.833 degrees)
        val cosHa = (cos(Math.toRadians(90.833)) /
                (cos(Math.toRadians(lat)) * cos(Math.toRadians(declination)))) -
                tan(Math.toRadians(lat)) * tan(Math.toRadians(declination))

        // Check for polar day/night
        val hasDayCycle = cosHa in -1.0..1.0
        val hourAngle = if (hasDayCycle) Math.toDegrees(acos(cosHa)) else 0.0

        // Solar noon (minutes from midnight UTC)
        val solarNoonMin = 720 - 4 * lon - eqTime + tzOffsetHours * 60

        val sunriseMin = solarNoonMin - hourAngle * 4
        val sunsetMin = solarNoonMin + hourAngle * 4

        // Day length
        val dayLengthMin = if (hasDayCycle) (sunsetMin - sunriseMin).roundToInt() else {
            if (cosHa < -1) 1440 else 0 // Polar day or polar night
        }

        // Current solar elevation
        val currentMinFromMidnight = (hour + tzOffsetHours) * 60.0 + minute
        val currentHourAngle = (currentMinFromMidnight / 4.0 - 180.0 - lon - eqTime / 4.0)
        val elevation = Math.toDegrees(
            asin(
                sin(Math.toRadians(lat)) * sin(Math.toRadians(declination)) +
                        cos(Math.toRadians(lat)) * cos(Math.toRadians(declination)) *
                        cos(Math.toRadians(currentHourAngle * 15))
            )
        )

        // UV index estimation from solar elevation
        val uvIndex = estimateUvIndex(elevation)

        // Golden hour: sun at 0-6 degrees above horizon
        val goldenMorning = minutesToTime((sunriseMin).roundToInt())
        val goldenEvening = minutesToTime((sunsetMin - 60).roundToInt())

        // Blue hour: sun at 4-8 degrees below horizon
        val blueMorning = minutesToTime((sunriseMin - 30).roundToInt())
        val blueEvening = minutesToTime((sunsetMin + 15).roundToInt())

        return SolarDay(
            sunrise = minutesToTime(sunriseMin.roundToInt()),
            sunset = minutesToTime(sunsetMin.roundToInt()),
            solarNoon = minutesToTime(solarNoonMin.roundToInt()),
            dayLength = "${dayLengthMin / 60}h ${dayLengthMin % 60}m",
            goldenHourMorning = goldenMorning,
            goldenHourEvening = goldenEvening,
            blueHourMorning = blueMorning,
            blueHourEvening = blueEvening,
            currentSolarElevation = elevation,
            estimatedUvIndex = uvIndex
        )
    }

    /**
     * Estimate UV index from solar elevation angle.
     * Simplified model — real UV depends on ozone, altitude, cloud cover.
     */
    private fun estimateUvIndex(elevation: Double): Int {
        if (elevation <= 0) return 0
        // UV roughly proportional to sin(elevation) with ozone correction
        val rawUv = sin(Math.toRadians(elevation)) * 14.0
        return rawUv.coerceIn(0.0, 11.0).roundToInt()
    }

    private fun julianDay(year: Int, month: Int, day: Int): Double {
        var y = year
        var m = month
        if (m <= 2) { y -= 1; m += 12 }
        val a = floor(y / 100.0)
        val b = 2 - a + floor(a / 4.0)
        return floor(365.25 * (y + 4716)) + floor(30.6001 * (m + 1)) + day + b - 1524.5
    }

    private fun minutesToTime(totalMinutes: Int): String {
        val mins = ((totalMinutes % 1440) + 1440) % 1440
        val h = mins / 60
        val m = mins % 60
        val ampm = if (h < 12) "AM" else "PM"
        val h12 = when {
            h == 0 -> 12
            h > 12 -> h - 12
            else -> h
        }
        return "$h12:${m.toString().padStart(2, '0')} $ampm"
    }

    /**
     * Seasonal daylight trend for the next 30 days.
     * Returns list of (date_label, day_length_minutes).
     */
    fun daylightTrend(lat: Double, lon: Double, days: Int = 30): List<Pair<String, Int>> {
        val cal = Calendar.getInstance()
        val tzOffset = cal.timeZone.rawOffset / 3600000

        return (0 until days).map { offset ->
            cal.timeInMillis = System.currentTimeMillis() + offset * 86400_000L
            val solar = calculate(lat, lon, tzOffset)
            val label = "${cal.get(Calendar.MONTH) + 1}/${cal.get(Calendar.DAY_OF_MONTH)}"
            val parts = solar.dayLength.split("h ", "m")
            val totalMin = (parts.getOrNull(0)?.toIntOrNull() ?: 0) * 60 +
                    (parts.getOrNull(1)?.toIntOrNull() ?: 0)
            label to totalMin
        }
    }
}
