package com.wifianalyzer.pro.scanner.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

object DateFormatter {

    private val dateTimeFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private val dateFmt = SimpleDateFormat("MMM dd, yyyy", Locale.US)
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun formatDateTime(timestamp: Long): String = dateTimeFmt.format(Date(timestamp))
    fun formatDate(timestamp: Long): String = dateFmt.format(Date(timestamp))
    fun formatTime(timestamp: Long): String = timeFmt.format(Date(timestamp))

    fun formatRelative(timestamp: Long): String {
        val diff = System.currentTimeMillis() - timestamp
        return when {
            diff < TimeUnit.MINUTES.toMillis(1) -> "just now"
            diff < TimeUnit.HOURS.toMillis(1) -> "${TimeUnit.MILLISECONDS.toMinutes(diff)} min ago"
            diff < TimeUnit.DAYS.toMillis(1) -> "${TimeUnit.MILLISECONDS.toHours(diff)} hr ago"
            diff < TimeUnit.DAYS.toMillis(7) -> "${TimeUnit.MILLISECONDS.toDays(diff)} days ago"
            else -> formatDate(timestamp)
        }
    }

    fun formatDuration(millis: Long): String {
        val s = TimeUnit.MILLISECONDS.toSeconds(millis)
        val m = s / 60
        val h = m / 60
        return when {
            h > 0 -> "${h}h ${m % 60}m"
            m > 0 -> "${m}m ${s % 60}s"
            else -> "${s}s"
        }
    }
}
