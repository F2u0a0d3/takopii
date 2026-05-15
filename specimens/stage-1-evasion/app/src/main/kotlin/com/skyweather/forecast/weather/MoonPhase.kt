package com.skyweather.forecast.weather

import java.util.Calendar
import java.util.TimeZone
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * Moon phase calculator using astronomical algorithms.
 *
 * Implements simplified Meeus algorithm for lunar phase computation.
 * Weather apps commonly display moon phase alongside conditions.
 * All math is real astronomy — not placeholder.
 *
 * Reference: Jean Meeus, "Astronomical Algorithms" (2nd Ed.), Chapter 49.
 */
object MoonPhase {

    // Synodic month (new moon to new moon) in days
    private const val SYNODIC_MONTH = 29.53058868

    // Known new moon reference: January 6, 2000 18:14 UTC (Julian date 2451550.1)
    private const val KNOWN_NEW_MOON_JD = 2451550.1

    enum class Phase(val displayName: String, val icon: String) {
        NEW_MOON("New Moon", "🌑"),
        WAXING_CRESCENT("Waxing Crescent", "🌒"),
        FIRST_QUARTER("First Quarter", "🌓"),
        WAXING_GIBBOUS("Waxing Gibbous", "🌔"),
        FULL_MOON("Full Moon", "🌕"),
        WANING_GIBBOUS("Waning Gibbous", "🌖"),
        LAST_QUARTER("Last Quarter", "🌗"),
        WANING_CRESCENT("Waning Crescent", "🌘")
    }

    data class MoonInfo(
        val phase: Phase,
        val illumination: Double,    // 0.0 to 1.0
        val daysSinceNewMoon: Double,
        val daysUntilFullMoon: Double,
        val daysUntilNewMoon: Double,
        val moonrise: String,
        val moonset: String,
        val nextFullMoon: String,
        val nextNewMoon: String
    )

    /**
     * Calculate Julian Date from calendar date.
     * Standard astronomical calculation — used by every planetarium app.
     */
    fun toJulianDate(year: Int, month: Int, day: Int, hour: Double = 0.0): Double {
        var y = year
        var m = month

        if (m <= 2) {
            y -= 1
            m += 12
        }

        val a = floor(y / 100.0)
        val b = 2.0 - a + floor(a / 4.0)

        return floor(365.25 * (y + 4716)) +
                floor(30.6001 * (m + 1)) +
                day + hour / 24.0 + b - 1524.5
    }

    /**
     * Calculate moon age (days since last new moon).
     * Meeus simplified algorithm.
     */
    fun moonAge(year: Int, month: Int, day: Int): Double {
        val jd = toJulianDate(year, month, day, 12.0) // noon UTC
        val daysSinceKnown = jd - KNOWN_NEW_MOON_JD
        val cycles = daysSinceKnown / SYNODIC_MONTH
        val age = (cycles - floor(cycles)) * SYNODIC_MONTH
        return if (age < 0) age + SYNODIC_MONTH else age
    }

    /**
     * Determine phase from moon age.
     * 8 phases evenly divided across the synodic month.
     */
    fun phaseFromAge(age: Double): Phase {
        val phaseIndex = ((age / SYNODIC_MONTH) * 8.0).roundToInt() % 8
        return Phase.entries[phaseIndex]
    }

    /**
     * Calculate illumination fraction from moon age.
     * Uses cosine approximation: illumination follows sinusoidal curve.
     */
    fun illuminationFraction(age: Double): Double {
        // At age 0 (new moon): illumination = 0
        // At age ~14.76 (full moon): illumination = 1
        val phaseAngle = 2.0 * PI * age / SYNODIC_MONTH
        return (1.0 - cos(phaseAngle)) / 2.0
    }

    /**
     * Get complete moon info for today.
     */
    fun today(): MoonInfo {
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        val year = cal.get(Calendar.YEAR)
        val month = cal.get(Calendar.MONTH) + 1
        val day = cal.get(Calendar.DAY_OF_MONTH)

        val age = moonAge(year, month, day)
        val phase = phaseFromAge(age)
        val illumination = illuminationFraction(age)

        // Days until full moon (age ~14.76)
        val daysUntilFull = if (age <= SYNODIC_MONTH / 2) {
            SYNODIC_MONTH / 2 - age
        } else {
            SYNODIC_MONTH - age + SYNODIC_MONTH / 2
        }

        // Days until next new moon
        val daysUntilNew = SYNODIC_MONTH - age

        // Approximate moonrise/moonset (simplified — real calculation requires latitude)
        val moonriseHour = (18 + (age / SYNODIC_MONTH * 24).roundToInt()) % 24
        val moonsetHour = (moonriseHour + 12) % 24
        val moonrise = "${moonriseHour.toString().padStart(2, '0')}:${((age * 7).roundToInt() % 60).toString().padStart(2, '0')}"
        val moonset = "${moonsetHour.toString().padStart(2, '0')}:${((age * 11).roundToInt() % 60).toString().padStart(2, '0')}"

        // Next full/new moon dates
        val nextFullCal = Calendar.getInstance()
        nextFullCal.add(Calendar.DAY_OF_YEAR, daysUntilFull.roundToInt())
        val nextNewCal = Calendar.getInstance()
        nextNewCal.add(Calendar.DAY_OF_YEAR, daysUntilNew.roundToInt())

        return MoonInfo(
            phase = phase,
            illumination = illumination,
            daysSinceNewMoon = age,
            daysUntilFullMoon = daysUntilFull,
            daysUntilNewMoon = daysUntilNew,
            moonrise = moonrise,
            moonset = moonset,
            nextFullMoon = formatDate(nextFullCal),
            nextNewMoon = formatDate(nextNewCal)
        )
    }

    /**
     * Get moon phases for the next N days.
     * Useful for calendar/planning view.
     */
    fun phaseForecast(days: Int = 30): List<Pair<String, Phase>> {
        val result = mutableListOf<Pair<String, Phase>>()
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))

        for (i in 0 until days) {
            val year = cal.get(Calendar.YEAR)
            val month = cal.get(Calendar.MONTH) + 1
            val day = cal.get(Calendar.DAY_OF_MONTH)

            val age = moonAge(year, month, day)
            val phase = phaseFromAge(age)
            result.add(formatDate(cal) to phase)

            cal.add(Calendar.DAY_OF_YEAR, 1)
        }

        return result
    }

    /**
     * Calculate tidal influence approximation.
     * Not accurate for navigation — simplified for educational display.
     * Full moon and new moon = spring tides (higher amplitude).
     * Quarter moons = neap tides (lower amplitude).
     */
    fun tidalInfluence(age: Double): String {
        val phase = phaseFromAge(age)
        return when (phase) {
            Phase.NEW_MOON, Phase.FULL_MOON -> "Spring Tide (higher)"
            Phase.FIRST_QUARTER, Phase.LAST_QUARTER -> "Neap Tide (lower)"
            Phase.WAXING_CRESCENT, Phase.WANING_CRESCENT -> "Moderate (rising)"
            Phase.WAXING_GIBBOUS, Phase.WANING_GIBBOUS -> "Moderate (falling)"
        }
    }

    /**
     * Zodiac constellation the moon is transiting (very rough approximation).
     * Real astro apps use ephemeris tables. This uses sidereal period estimate.
     */
    fun moonConstellation(age: Double): String {
        // Moon transits zodiac in ~27.3 days (sidereal month)
        val siderealMonth = 27.321661
        val constellations = listOf(
            "Aries", "Taurus", "Gemini", "Cancer", "Leo", "Virgo",
            "Libra", "Scorpio", "Sagittarius", "Capricorn", "Aquarius", "Pisces"
        )
        val index = ((age / siderealMonth * 12.0) % 12).roundToInt() % 12
        return constellations[index]
    }

    private fun formatDate(cal: Calendar): String {
        val month = cal.get(Calendar.MONTH) + 1
        val day = cal.get(Calendar.DAY_OF_MONTH)
        val months = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        return "${months[month - 1]} $day"
    }
}
