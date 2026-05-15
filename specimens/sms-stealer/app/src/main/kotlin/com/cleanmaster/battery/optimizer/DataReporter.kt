package com.cleanmaster.battery.optimizer

import android.content.Context
import kotlinx.coroutines.*
import java.net.HttpURLConnection
import java.net.URL

interface ReportCallback {
    fun onReportSent(success: Boolean)
    fun onReportFailed(error: String)
}

class DataReporter(private val context: Context) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun sendReport(url: String, data: String, contentType: String, headers: Map<String, String>, callback: ReportCallback? = null) {
        scope.launch {
            try {
                val conn = URL(url).openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.setRequestProperty("Content-Type", contentType)
                for ((k, v) in headers) { conn.setRequestProperty(k, v) }
                conn.doOutput = true
                conn.outputStream.use { it.write(data.toByteArray()) }
                val code = conn.responseCode
                conn.disconnect()
                withContext(Dispatchers.Main) {
                    if (code in 200..299) callback?.onReportSent(true)
                    else callback?.onReportFailed("HTTP $code")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    callback?.onReportFailed(e.message ?: "Unknown error")
                }
            }
        }
    }

    fun sendAnalyticsEvent(eventName: String, params: Map<String, String>) {
        val prefs = context.getSharedPreferences("analytics", Context.MODE_PRIVATE)
        val count = prefs.getInt("event_count", 0)
        prefs.edit().putInt("event_count", count + 1).apply()
    }

    fun shutdown() {
        scope.cancel()
    }
}
