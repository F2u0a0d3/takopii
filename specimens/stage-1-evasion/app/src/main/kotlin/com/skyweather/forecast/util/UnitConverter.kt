package com.skyweather.forecast.util

import kotlin.math.pow
import kotlin.math.roundToInt

/**
 * Comprehensive meteorological unit conversion utilities.
 *
 * Covers every unit system a weather app needs:
 * - Temperature (C/F/K)
 * - Wind speed (mph/km/h/m/s/knots/Beaufort)
 * - Pressure (hPa/mbar/inHg/mmHg/atm/psi)
 * - Distance/Visibility (km/mi/m/ft/nm)
 * - Precipitation (mm/in/cm)
 * - Humidity (relative/absolute/dew point)
 *
 * Real weather apps support multiple unit systems for international users.
 */
object UnitConverter {

    // ─── Temperature ─────────────────────────────────────────────

    fun celsiusToFahrenheit(c: Double): Double = c * 9.0 / 5.0 + 32.0
    fun fahrenheitToCelsius(f: Double): Double = (f - 32.0) * 5.0 / 9.0
    fun celsiusToKelvin(c: Double): Double = c + 273.15
    fun kelvinToCelsius(k: Double): Double = k - 273.15
    fun fahrenheitToKelvin(f: Double): Double = celsiusToKelvin(fahrenheitToCelsius(f))
    fun kelvinToFahrenheit(k: Double): Double = celsiusToFahrenheit(kelvinToCelsius(k))

    /**
     * Format temperature with unit symbol.
     * Rounds to nearest integer for display.
     */
    fun formatTemp(value: Double, unit: TempUnit): String = when (unit) {
        TempUnit.CELSIUS -> "${value.roundToInt()}°C"
        TempUnit.FAHRENHEIT -> "${celsiusToFahrenheit(value).roundToInt()}°F"
        TempUnit.KELVIN -> "${"%.1f".format(celsiusToKelvin(value))} K"
    }

    enum class TempUnit { CELSIUS, FAHRENHEIT, KELVIN }

    // ─── Wind Speed ──────────────────────────────────────────────

    fun mphToKmh(mph: Double): Double = mph * 1.60934
    fun kmhToMph(kmh: Double): Double = kmh / 1.60934
    fun mphToMs(mph: Double): Double = mph * 0.44704
    fun msToMph(ms: Double): Double = ms / 0.44704
    fun mphToKnots(mph: Double): Double = mph * 0.868976
    fun knotsToMph(knots: Double): Double = knots / 0.868976
    fun kmhToMs(kmh: Double): Double = kmh / 3.6
    fun msToKmh(ms: Double): Double = ms * 3.6
    fun knotsToMs(knots: Double): Double = knots * 0.514444
    fun msToKnots(ms: Double): Double = ms / 0.514444

    /**
     * Beaufort scale from wind speed in mph.
     * Returns Beaufort number (0-12).
     */
    fun mphToBeaufort(mph: Double): Int = when {
        mph < 1 -> 0
        mph < 4 -> 1
        mph < 8 -> 2
        mph < 13 -> 3
        mph < 19 -> 4
        mph < 25 -> 5
        mph < 32 -> 6
        mph < 39 -> 7
        mph < 47 -> 8
        mph < 55 -> 9
        mph < 64 -> 10
        mph < 73 -> 11
        else -> 12
    }

    fun formatWind(valueMph: Double, unit: WindUnit): String = when (unit) {
        WindUnit.MPH -> "${valueMph.roundToInt()} mph"
        WindUnit.KMH -> "${mphToKmh(valueMph).roundToInt()} km/h"
        WindUnit.MS -> "${"%.1f".format(mphToMs(valueMph))} m/s"
        WindUnit.KNOTS -> "${mphToKnots(valueMph).roundToInt()} kt"
        WindUnit.BEAUFORT -> "Bft ${mphToBeaufort(valueMph)}"
    }

    enum class WindUnit { MPH, KMH, MS, KNOTS, BEAUFORT }

    // ─── Pressure ────────────────────────────────────────────────

    fun hpaToInHg(hpa: Double): Double = hpa * 0.02953
    fun inHgToHpa(inHg: Double): Double = inHg / 0.02953
    fun hpaToMmHg(hpa: Double): Double = hpa * 0.75006
    fun mmHgToHpa(mmHg: Double): Double = mmHg / 0.75006
    fun hpaToAtm(hpa: Double): Double = hpa / 1013.25
    fun atmToHpa(atm: Double): Double = atm * 1013.25
    fun hpaToPsi(hpa: Double): Double = hpa * 0.014504

    fun formatPressure(valueHpa: Double, unit: PressureUnit): String = when (unit) {
        PressureUnit.HPA -> "${valueHpa.roundToInt()} hPa"
        PressureUnit.MBAR -> "${valueHpa.roundToInt()} mbar"  // 1 hPa = 1 mbar
        PressureUnit.INHG -> "${"%.2f".format(hpaToInHg(valueHpa))} inHg"
        PressureUnit.MMHG -> "${hpaToMmHg(valueHpa).roundToInt()} mmHg"
        PressureUnit.ATM -> "${"%.4f".format(hpaToAtm(valueHpa))} atm"
    }

    enum class PressureUnit { HPA, MBAR, INHG, MMHG, ATM }

    // ─── Distance / Visibility ───────────────────────────────────

    fun kmToMiles(km: Double): Double = km * 0.621371
    fun milesToKm(mi: Double): Double = mi / 0.621371
    fun kmToNauticalMiles(km: Double): Double = km * 0.539957
    fun metersToFeet(m: Double): Double = m * 3.28084
    fun feetToMeters(ft: Double): Double = ft / 3.28084

    fun formatVisibility(valueKm: Double, unit: DistanceUnit): String = when (unit) {
        DistanceUnit.KM -> "${"%.1f".format(valueKm)} km"
        DistanceUnit.MILES -> "${"%.1f".format(kmToMiles(valueKm))} mi"
        DistanceUnit.METERS -> "${(valueKm * 1000).roundToInt()} m"
        DistanceUnit.NM -> "${"%.1f".format(kmToNauticalMiles(valueKm))} nm"
    }

    enum class DistanceUnit { KM, MILES, METERS, NM }

    // ─── Precipitation ───────────────────────────────────────────

    fun mmToInches(mm: Double): Double = mm / 25.4
    fun inchesToMm(inches: Double): Double = inches * 25.4
    fun mmToCm(mm: Double): Double = mm / 10.0

    fun formatPrecip(valueMm: Double, unit: PrecipUnit): String = when (unit) {
        PrecipUnit.MM -> "${"%.1f".format(valueMm)} mm"
        PrecipUnit.IN -> "${"%.2f".format(mmToInches(valueMm))} in"
        PrecipUnit.CM -> "${"%.1f".format(mmToCm(valueMm))} cm"
    }

    enum class PrecipUnit { MM, IN, CM }

    // ─── Humidity Calculations ───────────────────────────────────

    /**
     * Calculate absolute humidity from relative humidity and temperature.
     * Uses Magnus formula for saturation vapor pressure.
     *
     * @param relativeHumidity Percentage (0-100)
     * @param tempC Temperature in Celsius
     * @return Absolute humidity in g/m³
     */
    fun absoluteHumidity(relativeHumidity: Int, tempC: Double): Double {
        val a = 17.27
        val b = 237.7
        val satVaporPressure = 6.112 * Math.exp(a * tempC / (b + tempC))
        val actualVaporPressure = satVaporPressure * relativeHumidity / 100.0
        // Absolute humidity = (2.16679 * e) / T(K)
        return 2.16679 * actualVaporPressure / (tempC + 273.15)
    }

    /**
     * Calculate mixing ratio (grams of water vapor per kilogram of dry air).
     */
    fun mixingRatio(relativeHumidity: Int, tempC: Double, pressureHpa: Double): Double {
        val a = 17.27
        val b = 237.7
        val satVaporPressure = 6.112 * Math.exp(a * tempC / (b + tempC))
        val actualVaporPressure = satVaporPressure * relativeHumidity / 100.0
        return 621.97 * actualVaporPressure / (pressureHpa - actualVaporPressure)
    }

    /**
     * Calculate wet bulb temperature (simplified).
     * Important for heat stress assessment.
     */
    fun wetBulbTemp(tempC: Double, relativeHumidity: Int): Double {
        val rh = relativeHumidity.toDouble()
        // Stull approximation (2011)
        return tempC * Math.atan(0.151977 * (rh + 8.313659).pow(0.5)) +
                Math.atan(tempC + rh) - Math.atan(rh - 1.676331) +
                0.00391838 * rh.pow(1.5) * Math.atan(0.023101 * rh) - 4.686035
    }

    // ─── Altitude / Density Altitude ─────────────────────────────

    /**
     * Pressure altitude from station pressure and sea-level reference.
     * Used by aviation weather displays.
     */
    fun pressureAltitudeFt(stationPressureHpa: Double): Double {
        // Standard atmosphere: 1013.25 hPa at sea level, decreases ~1 hPa per 30 ft
        return (1013.25 - stationPressureHpa) * 30.0
    }

    /**
     * Density altitude — corrects pressure altitude for temperature.
     * Critical for aviation performance calculations.
     */
    fun densityAltitudeFt(stationPressureHpa: Double, tempC: Double, elevationFt: Double): Double {
        val pressAlt = pressureAltitudeFt(stationPressureHpa) + elevationFt
        val stdTemp = 15.0 - (pressAlt / 1000.0 * 1.98) // ISA temperature at altitude
        val tempDeviation = tempC - stdTemp
        return pressAlt + (120.0 * tempDeviation)
    }
}
