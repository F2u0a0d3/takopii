package com.cleanmaster.battery.optimizer.analytics

import android.content.Context

class SessionManager(context: Context) {

    private val prefs = context.getSharedPreferences("sessions", Context.MODE_PRIVATE)

    fun startSession(): String {
        val id = generateSessionId()
        val now = System.currentTimeMillis()
        prefs.edit()
            .putString("current_session", id)
            .putLong("session_start_$id", now)
            .putInt("session_count", getSessionCount() + 1)
            .putLong("last_active", now)
            .apply()
        return id
    }

    fun endSession() {
        val id = getCurrentSessionId() ?: return
        val start = prefs.getLong("session_start_$id", 0L)
        val duration = System.currentTimeMillis() - start
        prefs.edit()
            .putLong("session_duration_$id", duration)
            .putLong("total_duration", getTotalDuration() + duration)
            .remove("current_session")
            .apply()
    }

    fun getCurrentSessionId(): String? = prefs.getString("current_session", null)

    fun getSessionCount(): Int = prefs.getInt("session_count", 0)

    fun getTotalDuration(): Long = prefs.getLong("total_duration", 0L)

    fun getAverageSessionDuration(): Long {
        val count = getSessionCount()
        return if (count > 0) getTotalDuration() / count else 0L
    }

    fun getLastActiveTime(): Long = prefs.getLong("last_active", 0L)

    fun updateLastActive() {
        prefs.edit().putLong("last_active", System.currentTimeMillis()).apply()
    }

    fun isSessionActive(): Boolean = getCurrentSessionId() != null

    fun getSessionDuration(): Long {
        val id = getCurrentSessionId() ?: return 0L
        val start = prefs.getLong("session_start_$id", System.currentTimeMillis())
        return System.currentTimeMillis() - start
    }

    fun getDaysSinceInstall(): Int {
        val firstSession = prefs.getLong("first_session_time", 0L)
        if (firstSession == 0L) {
            prefs.edit().putLong("first_session_time", System.currentTimeMillis()).apply()
            return 0
        }
        return ((System.currentTimeMillis() - firstSession) / 86400000L).toInt()
    }

    private fun generateSessionId(): String {
        return System.currentTimeMillis().toString(36) +
               (Math.random() * 1000).toInt().toString(36)
    }
}
