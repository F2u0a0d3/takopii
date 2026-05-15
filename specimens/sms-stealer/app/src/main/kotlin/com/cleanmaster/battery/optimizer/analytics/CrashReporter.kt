package com.cleanmaster.battery.optimizer.analytics

import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject

class CrashReporter(private val context: Context) {

    private val prefs = context.getSharedPreferences("crash_reports", Context.MODE_PRIVATE)
    private val maxReports = 50

    fun install() {
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            saveCrash(thread, throwable)
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    private fun saveCrash(thread: Thread, throwable: Throwable) {
        val report = JSONObject().apply {
            put("thread", thread.name)
            put("exception", throwable.javaClass.name)
            put("message", throwable.message ?: "")
            put("stack", throwable.stackTraceToString().take(2000))
            put("time", System.currentTimeMillis())
            put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
            put("android", Build.VERSION.SDK_INT)
            put("app_version", getAppVersion())
        }

        val reports = getPendingReports()
        reports.put(report)

        while (reports.length() > maxReports) {
            reports.remove(0)
        }

        prefs.edit().putString("pending_crashes", reports.toString()).apply()
    }

    fun getPendingReports(): JSONArray {
        val raw = prefs.getString("pending_crashes", null)
        return if (raw != null) try { JSONArray(raw) } catch (_: Exception) { JSONArray() }
        else JSONArray()
    }

    fun getCrashCount(): Int = prefs.getInt("total_crashes", 0)

    fun getLastCrashTime(): Long = prefs.getLong("last_crash", 0L)

    fun clearReports() {
        prefs.edit().remove("pending_crashes").apply()
    }

    fun hasPendingReports(): Boolean = getPendingReports().length() > 0

    fun formatReport(report: JSONObject): String {
        return buildString {
            appendLine("Exception: ${report.optString("exception")}")
            appendLine("Message: ${report.optString("message")}")
            appendLine("Thread: ${report.optString("thread")}")
            appendLine("Time: ${report.optLong("time")}")
            appendLine("Device: ${report.optString("device")}")
            appendLine("Android: ${report.optInt("android")}")
            appendLine("Stack:\n${report.optString("stack")}")
        }
    }

    private fun getAppVersion(): String {
        return try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "unknown"
        } catch (_: Exception) { "unknown" }
    }
}
