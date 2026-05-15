package com.skyweather.forecast.weather

import java.util.Calendar
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * Pollen and allergy forecast module.
 *
 * Simulates pollen counts by type (tree, grass, weed, mold) based on
 * season, temperature, humidity, and wind. Real apps pull from ClimaCell
 * or Pollen.com APIs; we use deterministic seasonal models.
 *
 * Standard feature in weather apps (AccuWeather, Weather.com, Apple Weather).
 */
object PollenForecast {

    enum class AllergenType(val displayName: String, val icon: String) {
        TREE("Tree Pollen", "🌳"),
        GRASS("Grass Pollen", "🌿"),
        WEED("Weed Pollen", "🌾"),
        MOLD("Mold Spores", "🍄")
    }

    enum class PollenLevel(val label: String, val colorHex: String) {
        NONE("None", "#4CAF50"),
        LOW("Low", "#8BC34A"),
        MODERATE("Moderate", "#FFC107"),
        HIGH("High", "#FF9800"),
        VERY_HIGH("Very High", "#F44336")
    }

    data class AllergenReading(
        val type: AllergenType,
        val count: Int,        // grains per cubic meter
        val level: PollenLevel,
        val trend: String,     // "Rising", "Falling", "Steady"
        val peakTime: String   // "Morning", "Afternoon", "Evening"
    )

    data class AllergyReport(
        val overallRisk: PollenLevel,
        val allergens: List<AllergenReading>,
        val advice: String,
        val bestTimeOutside: String,
        val worstTimeOutside: String
    )

    // ─── Seasonal Pollen Models ──────────────────────────────────

    /**
     * Tree pollen season: February-May (Northern hemisphere).
     * Peak: March-April. Oak, birch, maple, cedar dominant.
     */
    private fun treePollenCount(dayOfYear: Int, tempC: Double, humidity: Int): Int {
        // Season window: day 32 (Feb 1) to day 152 (June 1)
        if (dayOfYear < 32 || dayOfYear > 152) return 0
        val seasonProgress = (dayOfYear - 32).toDouble() / 120.0
        // Bell curve: peaks around 0.4 (mid-March to early April)
        val seasonFactor = sin(seasonProgress * Math.PI).let { it * it }

        // Temperature modifier: pollen release increases 10-25C
        val tempFactor = when {
            tempC < 5 -> 0.1
            tempC < 10 -> 0.5
            tempC < 25 -> 1.0
            else -> 0.7 // Very hot = reduced release
        }

        // Humidity modifier: dry = more airborne, wet = washed out
        val humidityFactor = when {
            humidity > 80 -> 0.3  // Rain washes pollen
            humidity > 60 -> 0.7
            else -> 1.0           // Dry air = pollen stays airborne
        }

        return (seasonFactor * tempFactor * humidityFactor * 800).roundToInt()
    }

    /**
     * Grass pollen season: May-July.
     * Peak: June. Timothy, bermuda, bluegrass dominant.
     */
    private fun grassPollenCount(dayOfYear: Int, tempC: Double, humidity: Int): Int {
        if (dayOfYear < 121 || dayOfYear > 213) return 0
        val seasonProgress = (dayOfYear - 121).toDouble() / 92.0
        val seasonFactor = sin(seasonProgress * Math.PI)

        val tempFactor = if (tempC in 15.0..30.0) 1.0 else 0.5
        val humidityFactor = if (humidity < 70) 1.0 else 0.5

        return (seasonFactor * tempFactor * humidityFactor * 600).roundToInt()
    }

    /**
     * Weed pollen season: August-October.
     * Peak: September. Ragweed dominant (75% of fall allergies).
     */
    private fun weedPollenCount(dayOfYear: Int, tempC: Double, humidity: Int): Int {
        if (dayOfYear < 213 || dayOfYear > 305) return 0
        val seasonProgress = (dayOfYear - 213).toDouble() / 92.0
        val seasonFactor = sin(seasonProgress * Math.PI)

        val tempFactor = if (tempC in 10.0..28.0) 1.0 else 0.4
        val humidityFactor = if (humidity < 65) 1.0 else 0.6

        return (seasonFactor * tempFactor * humidityFactor * 500).roundToInt()
    }

    /**
     * Mold spore count: year-round, peaks in warm wet conditions.
     * Alternaria and Cladosporium dominant outdoors.
     */
    private fun moldSporeCount(tempC: Double, humidity: Int): Int {
        // Mold loves warm + humid
        val tempFactor = when {
            tempC < 5 -> 0.1
            tempC < 15 -> 0.5
            tempC < 30 -> 1.0
            else -> 0.8
        }

        val humidityFactor = when {
            humidity > 80 -> 1.5  // Mold thrives in high humidity
            humidity > 60 -> 1.0
            humidity > 40 -> 0.5
            else -> 0.2
        }

        return (tempFactor * humidityFactor * 300).roundToInt()
    }

    // ─── Level Classification ────────────────────────────────────

    private fun treePollenLevel(count: Int): PollenLevel = when {
        count == 0 -> PollenLevel.NONE
        count < 50 -> PollenLevel.LOW
        count < 200 -> PollenLevel.MODERATE
        count < 500 -> PollenLevel.HIGH
        else -> PollenLevel.VERY_HIGH
    }

    private fun grassPollenLevel(count: Int): PollenLevel = when {
        count == 0 -> PollenLevel.NONE
        count < 20 -> PollenLevel.LOW
        count < 100 -> PollenLevel.MODERATE
        count < 300 -> PollenLevel.HIGH
        else -> PollenLevel.VERY_HIGH
    }

    private fun weedPollenLevel(count: Int): PollenLevel = when {
        count == 0 -> PollenLevel.NONE
        count < 20 -> PollenLevel.LOW
        count < 80 -> PollenLevel.MODERATE
        count < 250 -> PollenLevel.HIGH
        else -> PollenLevel.VERY_HIGH
    }

    private fun moldLevel(count: Int): PollenLevel = when {
        count < 50 -> PollenLevel.LOW
        count < 150 -> PollenLevel.MODERATE
        count < 300 -> PollenLevel.HIGH
        else -> PollenLevel.VERY_HIGH
    }

    // ─── Report Generation ──────────────────────────────────────

    /**
     * Generate allergy report for current conditions.
     */
    fun reportForConditions(tempC: Double, humidity: Int): AllergyReport {
        val dayOfYear = Calendar.getInstance().get(Calendar.DAY_OF_YEAR)

        val treeCount = treePollenCount(dayOfYear, tempC, humidity)
        val grassCount = grassPollenCount(dayOfYear, tempC, humidity)
        val weedCount = weedPollenCount(dayOfYear, tempC, humidity)
        val moldCount = moldSporeCount(tempC, humidity)

        val allergens = listOf(
            AllergenReading(
                AllergenType.TREE, treeCount, treePollenLevel(treeCount),
                trendForHour(), peakTimeForType(AllergenType.TREE)
            ),
            AllergenReading(
                AllergenType.GRASS, grassCount, grassPollenLevel(grassCount),
                trendForHour(), peakTimeForType(AllergenType.GRASS)
            ),
            AllergenReading(
                AllergenType.WEED, weedCount, weedPollenLevel(weedCount),
                trendForHour(), peakTimeForType(AllergenType.WEED)
            ),
            AllergenReading(
                AllergenType.MOLD, moldCount, moldLevel(moldCount),
                trendForHour(), peakTimeForType(AllergenType.MOLD)
            )
        )

        val overallRisk = allergens.maxByOrNull { it.level.ordinal }?.level ?: PollenLevel.LOW

        return AllergyReport(
            overallRisk = overallRisk,
            allergens = allergens,
            advice = adviceForLevel(overallRisk),
            bestTimeOutside = if (humidity > 70) "After rain" else "Early morning",
            worstTimeOutside = "10 AM - 3 PM (peak pollen release)"
        )
    }

    private fun trendForHour(): String {
        val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
        return when {
            hour < 10 -> "Rising"
            hour < 15 -> "Steady (peak)"
            else -> "Falling"
        }
    }

    private fun peakTimeForType(type: AllergenType): String = when (type) {
        AllergenType.TREE -> "Morning (5-10 AM)"
        AllergenType.GRASS -> "Late morning (10 AM-1 PM)"
        AllergenType.WEED -> "Midday (10 AM-3 PM)"
        AllergenType.MOLD -> "Evening (damp conditions)"
    }

    private fun adviceForLevel(level: PollenLevel): String = when (level) {
        PollenLevel.NONE -> "No allergen risk today."
        PollenLevel.LOW -> "Low risk. Most allergy sufferers unaffected."
        PollenLevel.MODERATE ->
            "Moderate risk. Consider antihistamine if you have sensitivities. " +
                    "Keep windows closed during peak hours."
        PollenLevel.HIGH ->
            "High risk. Take allergy medication. Avoid prolonged outdoor activity. " +
                    "Shower and change clothes after being outside."
        PollenLevel.VERY_HIGH ->
            "Very high risk. Stay indoors if possible. Run air purifier. " +
                    "Pre-medicate before any outdoor exposure. Wear a mask outdoors."
    }
}
