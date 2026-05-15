package com.wifianalyzer.pro.ui

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.wifianalyzer.pro.R

class LicenseActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        displayLicenses()
    }

    private fun displayLicenses() {
        val licenses = getLicenseEntries()
        val text = licenses.joinToString("\n\n") { "${it.name} (${it.version})\n${it.license}\n${it.url}" }
        findViewById<TextView>(R.id.textNetworkCount)?.text = text
    }

    private fun getLicenseEntries(): List<LicenseEntry> = listOf(
        LicenseEntry("Kotlin Coroutines", "1.8.1", "Apache License 2.0", "https://github.com/Kotlin/kotlinx.coroutines"),
        LicenseEntry("AndroidX AppCompat", "1.7.0", "Apache License 2.0", "https://developer.android.com/jetpack/androidx/releases/appcompat"),
        LicenseEntry("AndroidX Core KTX", "1.15.0", "Apache License 2.0", "https://developer.android.com/kotlin/ktx"),
        LicenseEntry("Material Components", "1.12.0", "Apache License 2.0", "https://material.io/develop/android"),
        LicenseEntry("AndroidX Work", "2.9.1", "Apache License 2.0", "https://developer.android.com/jetpack/androidx/releases/work"),
        LicenseEntry("AndroidX Lifecycle", "2.8.7", "Apache License 2.0", "https://developer.android.com/jetpack/androidx/releases/lifecycle"),
        LicenseEntry("AndroidX RecyclerView", "1.3.2", "Apache License 2.0", "https://developer.android.com/jetpack/androidx/releases/recyclerview")
    )

    data class LicenseEntry(val name: String, val version: String, val license: String, val url: String)
}
