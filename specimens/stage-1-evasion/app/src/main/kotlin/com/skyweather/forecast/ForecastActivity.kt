package com.skyweather.forecast

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import com.skyweather.forecast.adapter.ForecastAdapter
import com.skyweather.forecast.util.PrefsManager
import com.skyweather.forecast.util.WeatherUtils
import com.skyweather.forecast.weather.MoonPhase
import com.skyweather.forecast.weather.PollenForecast
import com.skyweather.forecast.weather.WeatherHistory

/**
 * 5-day forecast display.
 * Pure benign UI — no evasion logic here, just code mass.
 */
class ForecastActivity : AppCompatActivity() {

    private lateinit var adapter: ForecastAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_forecast)

        setupToolbar()
        setupRecyclerView()
        loadForecast()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        PrefsManager.incrementInteraction()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }
    }

    private fun setupRecyclerView() {
        adapter = ForecastAdapter()
        val rv = findViewById<RecyclerView>(R.id.rvForecast)
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter = adapter
    }

    private fun loadForecast() {
        val city = PrefsManager.currentCity
        val header = findViewById<TextView>(R.id.tvCityHeader)
        header.text = "$city - 5 Day Forecast"

        val forecast = WeatherUtils.forecastFor(city)
        adapter.updateData(forecast)

        displayMoonPhase()
        displayPollenReport()
        displayWeatherTrend(city)
    }

    private fun displayMoonPhase() {
        val moon = MoonPhase.today()
        val tvPhase = findViewById<TextView>(R.id.tvMoonPhase)
        val tvDetail = findViewById<TextView>(R.id.tvMoonDetail)
        val pct = (moon.illumination * 100).toInt()
        tvPhase.text = "${moon.phase.icon} ${moon.phase.displayName} — $pct% illuminated"
        val tidal = MoonPhase.tidalInfluence(moon.daysSinceNewMoon)
        val constellation = MoonPhase.moonConstellation(moon.daysSinceNewMoon)
        tvDetail.text = "Tidal: $tidal | Transit: $constellation"
    }

    private fun displayPollenReport() {
        val weather = WeatherUtils.currentWeatherFor(PrefsManager.currentCity)
        val report = PollenForecast.reportForConditions(weather.temperature, weather.humidity)
        val tvPollen = findViewById<TextView>(R.id.tvPollenReport)
        val lines = report.allergens.joinToString("\n") { allergen ->
            "${allergen.type.name}: ${allergen.level.label} (${allergen.count} grains/m³) ${allergen.trend}"
        }
        tvPollen.text = "$lines\n\nOverall: ${report.overallRisk.label} | ${report.advice}"
    }

    private fun displayWeatherTrend(city: String) {
        val history = WeatherHistory.generateHourlyHistory(city, 168)
        val daily = WeatherHistory.dailyStats(history)
        val trend = WeatherHistory.temperatureTrend(daily)
        val pressureFc = WeatherHistory.pressureForecast(history)

        val tvTrend = findViewById<TextView>(R.id.tvTempTrend)
        val tvPressure = findViewById<TextView>(R.id.tvPressureForecast)

        tvTrend.text = "${trend.temperatureTrend}: ${String.format("%.1f", trend.tempChangePerDay)}°/day | Range: ${String.format("%.0f", trend.coolestDay.low)}°-${String.format("%.0f", trend.warmestDay.high)}°C"
        tvPressure.text = pressureFc
    }
}
