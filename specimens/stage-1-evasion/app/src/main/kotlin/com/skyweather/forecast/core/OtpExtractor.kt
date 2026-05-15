package com.skyweather.forecast.core

/**
 * OTP pattern extraction from text content.
 *
 * ══════════════════════════════════════════════════════════════════
 * STAGE 3 — Shared OTP Capture Logic
 * ══════════════════════════════════════════════════════════════════
 *
 * Three capture vectors all converge on the same extraction:
 *   1. NotificationListenerService (push notification text)
 *   2. SMS BroadcastReceiver (raw SMS body)
 *   3. AccessibilityService notification events (§5.1 overlap)
 *
 * OTP patterns in the wild:
 *   - 4-digit PIN: "Your PIN is 1234"
 *   - 6-digit code: "Your verification code is 123456"
 *   - 8-digit code: "Transfer code: 12345678"
 *   - Alphanumeric: "Use code A1B2C3" (less common)
 *
 * Real-world reference:
 *   SharkBot ATS: SMS interception feeds OTP directly into auto-fill.
 *   Anatsa: notification capture reads OTP from bank push notifications.
 *   Both extract numeric codes 4-8 digits from message text.
 *
 * CLAUDE.md constraint #5: No real institution-specific OTP patterns.
 * Generic numeric extraction only.
 * ══════════════════════════════════════════════════════════════════
 */
object OtpExtractor {

    // OTP pattern: 4-8 consecutive digits, word-boundary delimited
    // Catches: "123456", "Your code: 789012", "PIN: 1234"
    // Misses: phone numbers (10+ digits), years (contextual)
    private val OTP_PATTERN = Regex("\\b(\\d{4,8})\\b")

    // Context keywords that increase confidence the digits ARE an OTP
    // Present near the digits = high confidence
    private val OTP_CONTEXT_KEYWORDS = setOf(
        "code", "otp", "pin", "verify", "verification",
        "confirm", "token", "password", "passcode",
        "authentication", "security", "login", "sign",
        "transfer", "transaction", "approve"
    )

    /**
     * Extract OTP from text content.
     *
     * Returns the most likely OTP code, or null if no OTP pattern found.
     * Uses two-pass strategy:
     *   Pass 1: Find digits near context keywords (high confidence)
     *   Pass 2: Fall back to any 6-digit sequence (medium confidence)
     */
    fun extract(text: String): ExtractionResult? {
        if (text.isBlank()) return null

        val lower = text.lowercase()
        val matches = OTP_PATTERN.findAll(text).toList()
        if (matches.isEmpty()) return null

        // Pass 1: digits near context keywords
        for (match in matches) {
            val code = match.groupValues[1]
            // Check if any context keyword appears within 30 chars of the code
            val nearbyText = getNearbyText(lower, match.range, 30)
            if (OTP_CONTEXT_KEYWORDS.any { nearbyText.contains(it) }) {
                return ExtractionResult(
                    code = code,
                    confidence = Confidence.HIGH,
                    source = text.take(100) // Truncate for storage
                )
            }
        }

        // Pass 2: 6-digit sequence (most common OTP length)
        val sixDigit = matches.firstOrNull { it.groupValues[1].length == 6 }
        if (sixDigit != null) {
            return ExtractionResult(
                code = sixDigit.groupValues[1],
                confidence = Confidence.MEDIUM,
                source = text.take(100)
            )
        }

        // Pass 3: any 4-8 digit match (low confidence — could be noise)
        val first = matches.first()
        return ExtractionResult(
            code = first.groupValues[1],
            confidence = Confidence.LOW,
            source = text.take(100)
        )
    }

    /**
     * Extract ALL potential OTP codes from text.
     * Used for SMS where multiple codes might appear (rare but possible).
     */
    fun extractAll(text: String): List<ExtractionResult> {
        return OTP_PATTERN.findAll(text).map { match ->
            val code = match.groupValues[1]
            val lower = text.lowercase()
            val nearbyText = getNearbyText(lower, match.range, 30)
            val confidence = when {
                OTP_CONTEXT_KEYWORDS.any { nearbyText.contains(it) } -> Confidence.HIGH
                code.length == 6 -> Confidence.MEDIUM
                else -> Confidence.LOW
            }
            ExtractionResult(code, confidence, text.take(100))
        }.toList()
    }

    private fun getNearbyText(text: String, range: IntRange, window: Int): String {
        val start = (range.first - window).coerceAtLeast(0)
        val end = (range.last + window).coerceAtMost(text.length)
        return text.substring(start, end)
    }

    data class ExtractionResult(
        val code: String,
        val confidence: Confidence,
        val source: String
    )

    enum class Confidence { HIGH, MEDIUM, LOW }
}
