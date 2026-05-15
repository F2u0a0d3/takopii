package com.wifianalyzer.pro.ui

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.wifianalyzer.pro.R

class FeedbackActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setupFeedback()
    }

    private fun setupFeedback() {
        val info = collectDeviceInfo()
        findViewById<TextView>(R.id.textNetworkCount)?.text = "Send Feedback\n\n$info"
    }

    private fun collectDeviceInfo(): String = buildString {
        appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("App: ${packageName}")
        try {
            val pInfo = packageManager.getPackageInfo(packageName, 0)
            appendLine("Version: ${pInfo.versionName}")
        } catch (_: Exception) {}
        appendLine("Display: ${resources.displayMetrics.widthPixels}x${resources.displayMetrics.heightPixels}")
        appendLine("Density: ${resources.displayMetrics.densityDpi}dpi")
        val rt = Runtime.getRuntime()
        appendLine("Memory: ${rt.freeMemory() / 1048576}MB free / ${rt.maxMemory() / 1048576}MB max")
        appendLine("Processors: ${rt.availableProcessors()}")
    }

    fun sendEmailFeedback(subject: String, body: String) {
        val intent = Intent(Intent.ACTION_SENDTO).apply {
            data = Uri.parse("mailto:")
            putExtra(Intent.EXTRA_SUBJECT, subject)
            putExtra(Intent.EXTRA_TEXT, body)
        }
        if (intent.resolveActivity(packageManager) != null) {
            startActivity(intent)
        }
    }
}
