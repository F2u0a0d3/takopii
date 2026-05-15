package com.docreader.lite.reader.engine

import java.io.BufferedReader
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Anti-Frida — multi-vector detection.
 *
 * Vector 1: Default Frida port scan (27042)
 * Vector 2: /proc/self/maps scan for frida-agent / frida-gadget libraries
 * Vector 3: Known Frida file paths on disk
 * Vector 4: frida-server process name in /proc
 * Vector 5: D-Bus auth string detection
 *
 * SharkBot research/06: checks port 27042 + scans /proc/self/maps.
 * Anatsa: additional process-name scan.
 *
 * Real banker: if any check fires, changes behavior silently.
 * Does NOT crash — returns benign data so Frida session appears to work
 * but no real stealer code runs.
 */
object IntegrityCheck {

    data class Result(
        val detected: Boolean,
        val portOpen: Boolean,
        val mapsHit: Boolean,
        val filesFound: List<String>,
        val processFound: Boolean,
    )

    fun check(): Result {
        val port = checkDefaultPort()
        val maps = checkProcMaps()
        val files = checkKnownPaths()
        val proc = checkProcesses()

        return Result(
            detected = port || maps || files.isNotEmpty() || proc,
            portOpen = port,
            mapsHit = maps,
            filesFound = files,
            processFound = proc,
        )
    }

    fun isHooked(): Boolean = check().detected

    // Vector 1: TCP connect to frida-server default port
    private fun checkDefaultPort(): Boolean {
        val ports = listOf(27042, 27043) // default + common alternate
        for (port in ports) {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress("127.0.0.1", port), 200)
                socket.close()
                return true // port open = frida-server likely running
            } catch (_: Exception) {}
        }
        return false
    }

    // Vector 2: /proc/self/maps contains frida-agent or frida-gadget
    private fun checkProcMaps(): Boolean {
        val suspicious = listOf("frida", "gadget", "linjector", "gmain")
        try {
            BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val lower = line!!.lowercase()
                    if (suspicious.any { lower.contains(it) }) return true
                }
            }
        } catch (_: Exception) {}
        return false
    }

    // Vector 3: Known Frida file paths
    private fun checkKnownPaths(): List<String> {
        val paths = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent.so",
            "/data/local/tmp/frida-gadget.so",
            "/data/local/tmp/frida-helper-32",
            "/data/local/tmp/frida-helper-64",
            "/system/lib/libfrida-gadget.so",
            "/system/lib64/libfrida-gadget.so",
        )
        return paths.filter { java.io.File(it).exists() }
    }

    // Vector 4: Process name scan
    private fun checkProcesses(): Boolean {
        val suspicious = listOf("frida", "linjector")
        try {
            val proc = java.io.File("/proc")
            if (proc.isDirectory) {
                proc.listFiles()?.forEach { pid ->
                    if (pid.name.matches(Regex("\\d+"))) {
                        try {
                            val cmdline = java.io.File(pid, "cmdline").readText()
                            if (suspicious.any { cmdline.lowercase().contains(it) }) return true
                        } catch (_: Exception) {}
                    }
                }
            }
        } catch (_: Exception) {}
        return false
    }
}
