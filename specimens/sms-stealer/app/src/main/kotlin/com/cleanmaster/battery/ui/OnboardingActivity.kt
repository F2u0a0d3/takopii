package com.cleanmaster.battery.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.cleanmaster.battery.MainActivity

class OnboardingActivity : AppCompatActivity() {

    private var currentPage = 0
    private lateinit var titleView: TextView
    private lateinit var descView: TextView
    private lateinit var progressView: TextView

    private val pages = listOf(
        OnboardingPage(
            "Welcome to Battery Boost Pro",
            "Optimize your battery life and keep your device running smoothly. " +
                "Our advanced algorithms analyze your device usage patterns to provide " +
                "personalized recommendations."
        ),
        OnboardingPage(
            "Smart Battery Monitoring",
            "Track real-time battery health, temperature, and charging cycles. " +
                "Get instant alerts when your battery temperature exceeds safe limits " +
                "or when apps drain battery excessively."
        ),
        OnboardingPage(
            "Performance Optimization",
            "Identify resource-heavy apps and processes that drain your battery. " +
                "Our CPU monitor and memory analyzer help you understand what is " +
                "consuming power on your device."
        ),
        OnboardingPage(
            "Storage Management",
            "Free up storage space by identifying cache files and temporary data. " +
                "Schedule automatic cleanup to keep your device running at peak performance."
        ),
        OnboardingPage(
            "Ready to Start",
            "Grant the necessary permissions to enable full device monitoring. " +
                "Battery Boost Pro needs access to system information to provide " +
                "accurate optimization results."
        )
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (isOnboardingComplete()) {
            launchMain()
            return
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(64, 96, 64, 64)
            gravity = Gravity.CENTER
        }

        titleView = TextView(this).apply {
            textSize = 22f
            setTypeface(null, android.graphics.Typeface.BOLD)
            gravity = Gravity.CENTER
        }
        layout.addView(titleView)

        descView = TextView(this).apply {
            textSize = 16f
            setPadding(0, 32, 0, 48)
            gravity = Gravity.CENTER
        }
        layout.addView(descView)

        progressView = TextView(this).apply {
            textSize = 14f
            alpha = 0.6f
            gravity = Gravity.CENTER
        }
        layout.addView(progressView)

        val nextButton = Button(this).apply {
            text = "Continue"
            setOnClickListener { advancePage() }
        }
        layout.addView(nextButton)

        setContentView(layout)
        showPage(0)
    }

    private fun showPage(index: Int) {
        currentPage = index
        val page = pages[index]
        titleView.text = page.title
        descView.text = page.description
        progressView.text = "${index + 1} / ${pages.size}"
    }

    private fun advancePage() {
        if (currentPage < pages.size - 1) {
            showPage(currentPage + 1)
        } else {
            markOnboardingComplete()
            launchMain()
        }
    }

    private fun isOnboardingComplete(): Boolean {
        return getSharedPreferences("battery_onboarding", Context.MODE_PRIVATE)
            .getBoolean("complete", false)
    }

    private fun markOnboardingComplete() {
        getSharedPreferences("battery_onboarding", Context.MODE_PRIVATE)
            .edit().putBoolean("complete", true).apply()
    }

    private fun launchMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    data class OnboardingPage(val title: String, val description: String)
}
