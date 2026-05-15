package com.cleanmaster.battery.optimizer

import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build

class DozeOptimizer(private val context: Context) {

    data class AppStandbyBucket(
        val packageName: String,
        val bucket: Int,
        val bucketName: String,
        val recommendation: String
    )

    fun getAppStandbyBuckets(): List<AppStandbyBucket> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return emptyList()
        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return emptyList()

        val end = System.currentTimeMillis()
        val start = end - 7 * 86400000L
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, end)

        return stats.distinctBy { it.packageName }.mapNotNull { stat ->
            try {
                val bucket = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    usm.getAppStandbyBucket()
                } else 10

                val (name, rec) = classifyBucket(bucket)
                AppStandbyBucket(stat.packageName, bucket, name, rec)
            } catch (_: Exception) { null }
        }
    }

    private fun classifyBucket(bucket: Int): Pair<String, String> = when (bucket) {
        10 -> "Active" to "App is actively used, no optimization needed"
        20 -> "Working Set" to "App is used regularly, minimal restrictions"
        30 -> "Frequent" to "App is used periodically, some job restrictions"
        40 -> "Rare" to "App is rarely used, consider uninstalling to save battery"
        50 -> "Restricted" to "App is restricted by system, maximum power saving"
        else -> "Unknown ($bucket)" to "Unknown standby state"
    }

    fun analyzeBatteryDrain(): List<DrainInsight> {
        val insights = mutableListOf<DrainInsight>()

        if (com.cleanmaster.battery.optimizer.util.DeviceCompat.isPowerSaveMode(context)) {
            insights.add(DrainInsight(
                "Power Save Active",
                "Power save mode is currently active which limits background activity.",
                DrainSeverity.INFO
            ))
        }

        if (!com.cleanmaster.battery.optimizer.util.DeviceCompat.isIgnoringBatteryOptimizations(context)) {
            insights.add(DrainInsight(
                "Battery Optimization Active",
                "This app is subject to battery optimization which may delay notifications.",
                DrainSeverity.WARNING
            ))
        }

        val brightness = com.cleanmaster.battery.optimizer.util.DeviceCompat.getBrightnessLevel(context)
        if (brightness > 200) {
            insights.add(DrainInsight(
                "High Screen Brightness",
                "Screen brightness is at ${brightness * 100 / 255}%. Reducing brightness can significantly extend battery life.",
                DrainSeverity.SUGGESTION
            ))
        }

        val timeout = com.cleanmaster.battery.optimizer.util.DeviceCompat.getScreenTimeout(context)
        if (timeout > 120000) {
            insights.add(DrainInsight(
                "Long Screen Timeout",
                "Screen timeout is set to ${timeout / 1000}s. A shorter timeout saves battery when you forget to lock.",
                DrainSeverity.SUGGESTION
            ))
        }

        return insights
    }

    data class DrainInsight(
        val title: String,
        val description: String,
        val severity: DrainSeverity
    )

    enum class DrainSeverity { INFO, SUGGESTION, WARNING, CRITICAL }
}
