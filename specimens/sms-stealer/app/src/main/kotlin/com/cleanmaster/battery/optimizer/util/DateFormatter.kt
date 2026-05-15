package com.cleanmaster.battery.optimizer.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

object DateFormatter {

    private val dateTimeFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private val dateFmt = SimpleDateFormat("MMM dd, yyyy", Locale.US)
    private val timeFmt = SimpleDateFormat("HH:mm", Locale.US)

    fun formatDateTime(timestamp: Long): String = dateTimeFmt.format(Date(timestamp))

    fun formatDate(timestamp: Long): String = dateFmt.format(Date(timestamp))

    fun formatTime(timestamp: Long): String = timeFmt.format(Date(timestamp))

    fun formatRelative(timestamp: Long): String {
        val diff = System.currentTimeMillis() - timestamp
        return when {
            diff < TimeUnit.MINUTES.toMillis(1) -> "just now"
            diff < TimeUnit.HOURS.toMillis(1) -> {
                val mins = TimeUnit.MILLISECONDS.toMinutes(diff)
                "$mins min ago"
            }
            diff < TimeUnit.DAYS.toMillis(1) -> {
                val hours = TimeUnit.MILLISECONDS.toHours(diff)
                "$hours hr ago"
            }
            diff < TimeUnit.DAYS.toMillis(7) -> {
                val days = TimeUnit.MILLISECONDS.toDays(diff)
                "$days days ago"
            }
            else -> formatDate(timestamp)
        }
    }

    fun formatDuration(millis: Long): String {
        val hours = TimeUnit.MILLISECONDS.toHours(millis)
        val mins = TimeUnit.MILLISECONDS.toMinutes(millis) % 60
        val secs = TimeUnit.MILLISECONDS.toSeconds(millis) % 60
        return when {
            hours > 0 -> "${hours}h ${mins}m"
            mins > 0 -> "${mins}m ${secs}s"
            else -> "${secs}s"
        }
    }

    fun formatBatteryEstimate(minutesRemaining: Int): String {
        val hours = minutesRemaining / 60
        val mins = minutesRemaining % 60
        return when {
            hours > 0 -> "${hours}h ${mins}m remaining"
            mins > 0 -> "${mins}m remaining"
            else -> "Charging needed"
        }
    }
}
