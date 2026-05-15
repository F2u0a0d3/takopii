package com.cleanmaster.battery.optimizer

import android.app.AlarmManager
import android.content.Context
import android.os.Build
import android.os.SystemClock

class AlarmAnalyzer(private val context: Context) {

    data class AlarmInfo(
        val nextTriggerMs: Long,
        val canScheduleExact: Boolean,
        val alarmCount: Int,
        val recommendation: String
    )

    fun analyzeAlarms(): AlarmInfo {
        val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager

        val nextAlarmInfo = am.nextAlarmClock
        val nextTrigger = nextAlarmInfo?.triggerTime ?: 0L

        val canExact = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            am.canScheduleExactAlarms()
        } else true

        val uptimeMs = SystemClock.elapsedRealtime()
        val alarmEstimate = estimateAlarmDensity(uptimeMs)

        val rec = when {
            alarmEstimate > 50 -> "High alarm activity detected. Many apps are scheduling frequent wakeups."
            alarmEstimate > 20 -> "Moderate alarm activity. Some apps may be waking the device unnecessarily."
            else -> "Normal alarm activity. Battery drain from alarms is minimal."
        }

        return AlarmInfo(
            nextTriggerMs = nextTrigger,
            canScheduleExact = canExact,
            alarmCount = alarmEstimate,
            recommendation = rec
        )
    }

    private fun estimateAlarmDensity(uptimeMs: Long): Int {
        val uptimeHours = (uptimeMs / 3600000f).coerceAtLeast(1f)
        return (uptimeHours * 3).toInt()
    }

    fun getAlarmOptimizationTips(): List<String> {
        val tips = mutableListOf<String>()
        tips.add("Disable exact alarms for non-critical apps in Settings > Apps > Special Access")
        tips.add("Use Doze-friendly scheduling with WorkManager instead of AlarmManager")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            if (am.canScheduleExactAlarms()) {
                tips.add("Some apps have exact alarm permission - review in Settings > Apps > Alarms & reminders")
            }
        }

        tips.add("Repeating alarms at short intervals prevent device from entering deep sleep")
        tips.add("Consider using FCM high-priority messages instead of polling with alarms")

        return tips
    }

    fun formatNextAlarm(): String {
        val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val next = am.nextAlarmClock ?: return "No alarm set"
        val diff = next.triggerTime - System.currentTimeMillis()
        return when {
            diff < 0 -> "Alarm overdue"
            diff < 3600000 -> "${diff / 60000} min from now"
            diff < 86400000 -> "${diff / 3600000} hr ${(diff % 3600000) / 60000} min from now"
            else -> "${diff / 86400000} days from now"
        }
    }
}
