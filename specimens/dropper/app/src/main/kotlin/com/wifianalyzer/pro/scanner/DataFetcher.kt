package com.wifianalyzer.pro.scanner

import kotlinx.coroutines.*
import java.net.HttpURLConnection
import java.net.URL

interface FetchCallback {
    fun onSuccess(data: ByteArray)
    fun onFailure(error: String)
}

class DataFetcher {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun fetchString(url: String, headers: Map<String, String> = emptyMap()): String? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 10000
            conn.readTimeout = 60000
            for ((k, v) in headers) conn.setRequestProperty(k, v)
            val result = conn.inputStream.bufferedReader().readText()
            conn.disconnect()
            result
        } catch (_: Exception) { null }
    }

    fun fetchBytes(url: String, callback: FetchCallback? = null): ByteArray? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 10000
            conn.readTimeout = 60000
            val bytes = conn.inputStream.readBytes()
            conn.disconnect()
            callback?.onSuccess(bytes)
            bytes
        } catch (e: Exception) {
            callback?.onFailure(e.message ?: "Unknown")
            null
        }
    }

    fun fetchAsync(url: String, callback: FetchCallback) {
        scope.launch {
            val bytes = fetchBytes(url)
            withContext(Dispatchers.Main) {
                if (bytes != null) callback.onSuccess(bytes)
                else callback.onFailure("Fetch failed")
            }
        }
    }

    fun shutdown() { scope.cancel() }
}
