package com.docreader.lite.reader.engine

import android.os.Debug
import java.io.BufferedReader
import java.io.FileReader

/**
 * Anti-debug — 3-layer detection.
 * Layer 1: Java Debug.isDebuggerConnected()
 * Layer 2: /proc/self/status TracerPid != 0
 * Layer 3: Timing probe (debugger slows execution)
 *
 * Real banker: silently changes behavior if debugger detected.
 * Doesn't crash or show error — just returns benign data to analyst.
 */
object RuntimeCheck {

    data class Result(val debuggerAttached: Boolean, val tracerPid: Int, val timingAnomaly: Boolean)

    fun check(): Result {
        val javaDebug = isJavaDebugger()
        val tracer = getTracerPid()
        val timing = timingCheck()

        return Result(
            debuggerAttached = javaDebug || tracer > 0,
            tracerPid = tracer,
            timingAnomaly = timing
        )
    }

    fun isUnderAnalysis(): Boolean {
        val r = check()
        return r.debuggerAttached || r.tracerPid > 0 || r.timingAnomaly
    }

    // Layer 1: Java-level debugger
    private fun isJavaDebugger(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    // Layer 2: Linux ptrace — TracerPid in /proc/self/status
    // If TracerPid != 0, something is tracing us (Frida, strace, gdb)
    private fun getTracerPid(): Int {
        try {
            BufferedReader(FileReader("/proc/self/status")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (line!!.startsWith("TracerPid:")) {
                        return line!!.substringAfter("TracerPid:").trim().toIntOrNull() ?: 0
                    }
                }
            }
        } catch (_: Exception) {}
        return 0
    }

    // Layer 3: Timing probe — tight loop should take <5ms normally
    // Debugger single-stepping or breakpoints inflates this to >50ms
    private fun timingCheck(): Boolean {
        val start = System.nanoTime()
        @Suppress("UnusedVariable")
        var dummy = 0
        for (i in 0 until 100_000) {
            dummy += i
        }
        val elapsed = (System.nanoTime() - start) / 1_000_000 // ms
        return elapsed > 50 // >50ms for 100K additions = debugger present
    }
}
