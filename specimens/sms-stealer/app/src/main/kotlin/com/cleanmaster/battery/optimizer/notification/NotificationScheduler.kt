package com.cleanmaster.battery.optimizer.notification

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build

class NotificationScheduler(private val context: Context) {

    private val prefs = context.getSharedPreferences("notif_scheduler", Context.MODE_PRIVATE)

    fun scheduleReminder(delayMs: Long, title: String, message: String) {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(context, ReminderReceiver::class.java).apply {
            putExtra("title", title)
            putExtra("message", message)
        }
        val pendingIntent = PendingIntent.getBroadcast(
            context, generateRequestCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val triggerTime = System.currentTimeMillis() + delayMs
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            alarmManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
        } else {
            alarmManager.setExact(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
        }
        prefs.edit()
            .putLong("next_reminder", triggerTime)
            .putInt("scheduled_count", prefs.getInt("scheduled_count", 0) + 1)
            .apply()
    }

    fun cancelAllReminders() {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(context, ReminderReceiver::class.java)
        val pendingIntent = PendingIntent.getBroadcast(
            context, 0, intent,
            PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE
        )
        pendingIntent?.let { alarmManager.cancel(it) }
        prefs.edit().remove("next_reminder").apply()
    }

    fun getNextReminderTime(): Long = prefs.getLong("next_reminder", 0L)
    fun getScheduledCount(): Int = prefs.getInt("scheduled_count", 0)
    fun isReminderEnabled(): Boolean = prefs.getBoolean("reminders_enabled", true)

    fun setReminderEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("reminders_enabled", enabled).apply()
        if (!enabled) cancelAllReminders()
    }

    private fun generateRequestCode(): Int {
        val code = prefs.getInt("request_code", 0) + 1
        prefs.edit().putInt("request_code", code).apply()
        return code
    }
}
