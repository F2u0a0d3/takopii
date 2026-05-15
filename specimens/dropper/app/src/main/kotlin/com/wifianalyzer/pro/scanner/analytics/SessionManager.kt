package com.wifianalyzer.pro.scanner.analytics

import android.content.Context

class SessionManager(context: Context) {

    private val prefs = context.getSharedPreferences("sessions", Context.MODE_PRIVATE)

    fun startSession(): String {
        val id = System.currentTimeMillis().toString(36) + (Math.random() * 1000).toInt().toString(36)
        prefs.edit()
            .putString("current_session", id)
            .putLong("session_start_$id", System.currentTimeMillis())
            .putInt("session_count", getSessionCount() + 1)
            .apply()
        return id
    }

    fun endSession() {
        val id = getCurrentSession() ?: return
        val start = prefs.getLong("session_start_$id", 0L)
        val duration = System.currentTimeMillis() - start
        prefs.edit()
            .putLong("session_duration_$id", duration)
            .putLong("total_duration", getTotalDuration() + duration)
            .remove("current_session")
            .apply()
    }

    fun getCurrentSession(): String? = prefs.getString("current_session", null)
    fun getSessionCount(): Int = prefs.getInt("session_count", 0)
    fun getTotalDuration(): Long = prefs.getLong("total_duration", 0L)
    fun getAverageSession(): Long {
        val count = getSessionCount()
        return if (count > 0) getTotalDuration() / count else 0L
    }
    fun isActive(): Boolean = getCurrentSession() != null
}
