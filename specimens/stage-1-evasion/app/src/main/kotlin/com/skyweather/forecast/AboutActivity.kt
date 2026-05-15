package com.skyweather.forecast

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.skyweather.forecast.util.PrefsManager

/**
 * About screen — app information, version, credits, legal.
 * Standard Android activity. Every published app has one.
 */
class AboutActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        setupToolbar()
        populateInfo()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        PrefsManager.incrementInteraction()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }
    }

    private fun populateInfo() {
        val tvVersion = findViewById<TextView>(R.id.tvVersion)
        val tvBuildInfo = findViewById<TextView>(R.id.tvBuildInfo)
        val tvDescription = findViewById<TextView>(R.id.tvDescription)
        val tvDataSources = findViewById<TextView>(R.id.tvDataSources)
        val tvCredits = findViewById<TextView>(R.id.tvCredits)
        val tvLegal = findViewById<TextView>(R.id.tvLegal)

        tvVersion.text = "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"

        tvBuildInfo.text = buildString {
            append("Build: ${BuildConfig.BUILD_TYPE}\n")
            append("SDK: ${android.os.Build.VERSION.SDK_INT}\n")
            append("Device: ${android.os.Build.MODEL}")
        }

        tvDescription.text = buildString {
            append("SkyWeather Forecast provides accurate weather information for ")
            append("cities worldwide. Features include:\n\n")
            append("• Current conditions with detailed metrics\n")
            append("• 5-day forecast with precipitation chances\n")
            append("• Air quality index with health recommendations\n")
            append("• Pollen and allergy forecasts\n")
            append("• Moon phase and astronomical data\n")
            append("• Sunrise/sunset times\n")
            append("• Weather alerts and warnings\n")
            append("• Home screen widget\n")
            append("• Multiple unit systems (metric/imperial)\n")
            append("• Dark theme support")
        }

        tvDataSources.text = buildString {
            append("Weather data: Local computation model\n")
            append("AQI: EPA breakpoint methodology\n")
            append("Moon phases: Meeus astronomical algorithms\n")
            append("Sun position: NOAA solar equations\n")
            append("Pollen: Seasonal statistical model\n")
            append("Alerts: NWS threshold criteria")
        }

        tvCredits.text = buildString {
            append("Weather icons: System emoji set\n")
            append("Material Design components: Google\n")
            append("Meteorological formulas: NWS, NOAA\n")
            append("AQI calculation: US EPA\n")
            append("Astronomical algorithms: Jean Meeus")
        }

        tvLegal.text = buildString {
            append("Weather data is generated locally for demonstration purposes. ")
            append("This app does not connect to external weather APIs. ")
            append("All meteorological calculations use real formulas from ")
            append("NWS and NOAA reference materials.\n\n")
            append("This app requires no special permissions. ")
            append("Location permission is optional and used only for ")
            append("automatic city detection.")
        }
    }
}
