package com.cleanmaster.battery.optimizer

import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager

data class AppUsageStat(
    val packageName: String,
    val appName: String,
    val totalTimeForegroundMs: Long,
    val lastUsedTimestamp: Long,
    val totalTimeMinutes: Int
)

class AppUsageAnalyzer(private val context: Context) {

    private val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager

    fun getTopApps(daysBack: Int = 7, limit: Int = 20): List<AppUsageStat> {
        val end = System.currentTimeMillis()
        val start = end - (daysBack.toLong() * 24 * 60 * 60 * 1000)
        val stats = usm?.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, end)
            ?: return emptyList()

        return stats
            .filter { it.totalTimeInForeground > 0 }
            .groupBy { it.packageName }
            .map { (pkg, entries) ->
                val totalMs = entries.sumOf { it.totalTimeInForeground }
                val lastUsed = entries.maxOf { it.lastTimeUsed }
                val appName = try {
                    val ai = context.packageManager.getApplicationInfo(pkg, 0)
                    context.packageManager.getApplicationLabel(ai).toString()
                } catch (_: PackageManager.NameNotFoundException) { pkg }
                AppUsageStat(pkg, appName, totalMs, lastUsed, (totalMs / 60_000).toInt())
            }
            .sortedByDescending { it.totalTimeForegroundMs }
            .take(limit)
    }

    fun getDrainRating(foregroundMinutes: Int): String = when {
        foregroundMinutes > 300 -> "Heavy"
        foregroundMinutes > 120 -> "Moderate"
        foregroundMinutes > 30 -> "Light"
        else -> "Minimal"
    }

    fun hasUsagePermission(): Boolean {
        val stats = usm?.queryUsageStats(
            UsageStatsManager.INTERVAL_DAILY,
            System.currentTimeMillis() - 86_400_000,
            System.currentTimeMillis()
        )
        return stats != null && stats.isNotEmpty()
    }
}
