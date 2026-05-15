package com.skyweather.forecast.util

import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

/**
 * Date/time formatting utilities for weather display.
 * More benign code mass — standard utility class.
 */
object DateUtils {

    private val timeFormat = SimpleDateFormat("h:mm a", Locale.getDefault())
    private val dateFormat = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    private val dayFormat = SimpleDateFormat("EEEE", Locale.getDefault())
    private val shortDayFormat = SimpleDateFormat("EEE", Locale.getDefault())

    fun formatTime(timestamp: Long): String = timeFormat.format(Date(timestamp))

    fun formatDate(timestamp: Long): String = dateFormat.format(Date(timestamp))

    fun formatDayOfWeek(timestamp: Long): String = dayFormat.format(Date(timestamp))

    fun formatShortDay(timestamp: Long): String = shortDayFormat.format(Date(timestamp))

    /** "5 minutes ago", "2 hours ago", etc */
    fun relativeTime(timestamp: Long): String {
        val now = System.currentTimeMillis()
        val diff = now - timestamp

        return when {
            diff < TimeUnit.MINUTES.toMillis(1) -> "just now"
            diff < TimeUnit.HOURS.toMillis(1) -> {
                val mins = TimeUnit.MILLISECONDS.toMinutes(diff)
                "$mins ${if (mins == 1L) "minute" else "minutes"} ago"
            }
            diff < TimeUnit.DAYS.toMillis(1) -> {
                val hours = TimeUnit.MILLISECONDS.toHours(diff)
                "$hours ${if (hours == 1L) "hour" else "hours"} ago"
            }
            else -> {
                val days = TimeUnit.MILLISECONDS.toDays(diff)
                "$days ${if (days == 1L) "day" else "days"} ago"
            }
        }
    }

    /** Get current hour for day/night determination */
    fun currentHour(): Int = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)

    /** Is it currently daytime (6am - 6pm) */
    fun isDaytime(): Boolean = currentHour() in 6..17

    /** Sunrise/sunset approximation for display */
    fun approximateSunrise(lat: Double): String {
        // Simple approximation — real apps use astronomical calculation
        val baseHour = 6 + (lat / 30).toInt().coerceIn(-2, 2)
        return "${baseHour}:${(15 + (lat.toInt() % 30)).toString().padStart(2, '0')} AM"
    }

    fun approximateSunset(lat: Double): String {
        val baseHour = 6 + (lat / 20).toInt().coerceIn(-3, 3)
        return "${baseHour}:${(30 + (lat.toInt() % 25)).toString().padStart(2, '0')} PM"
    }

    /** Get timezone offset string */
    fun timezoneOffset(): String {
        val tz = TimeZone.getDefault()
        val offset = tz.rawOffset
        val hours = TimeUnit.MILLISECONDS.toHours(offset.toLong())
        val minutes = TimeUnit.MILLISECONDS.toMinutes(offset.toLong()) % 60
        return "UTC${if (hours >= 0) "+" else ""}$hours:${minutes.toString().padStart(2, '0')}"
    }
}
