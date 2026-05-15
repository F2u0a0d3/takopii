package com.cleanmaster.battery.optimizer.sync

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class SyncManager(private val context: Context) {

    private val prefs = context.getSharedPreferences("sync_state", Context.MODE_PRIVATE)
    private val maxPendingItems = 500

    fun queueItem(type: String, data: JSONObject) {
        val item = JSONObject().apply {
            put("type", type)
            put("data", data)
            put("queued", System.currentTimeMillis())
            put("retries", 0)
        }
        val queue = getQueue()
        queue.put(item)
        trimQueue(queue)
        saveQueue(queue)
        updateStats(type)
    }

    fun getQueue(): JSONArray {
        val raw = prefs.getString("sync_queue", null) ?: return JSONArray()
        return try { JSONArray(raw) } catch (_: Exception) { JSONArray() }
    }

    fun getPendingCount(): Int = getQueue().length()

    fun getQueueSizeBytes(): Long {
        val raw = prefs.getString("sync_queue", "") ?: ""
        return raw.length.toLong() * 2
    }

    fun dequeueItems(count: Int): List<JSONObject> {
        val queue = getQueue()
        val items = mutableListOf<JSONObject>()
        val remaining = JSONArray()

        for (i in 0 until queue.length()) {
            if (i < count) {
                items.add(queue.getJSONObject(i))
            } else {
                remaining.put(queue.getJSONObject(i))
            }
        }
        saveQueue(remaining)
        return items
    }

    fun markFailed(item: JSONObject) {
        val retries = item.optInt("retries", 0) + 1
        if (retries < 3) {
            item.put("retries", retries)
            val queue = getQueue()
            queue.put(item)
            saveQueue(queue)
        }
        prefs.edit().putInt("fail_count", prefs.getInt("fail_count", 0) + 1).apply()
    }

    fun getLastSyncTime(): Long = prefs.getLong("last_sync", 0L)

    fun markSynced() {
        prefs.edit()
            .putLong("last_sync", System.currentTimeMillis())
            .putInt("sync_count", prefs.getInt("sync_count", 0) + 1)
            .apply()
    }

    fun getSyncCount(): Int = prefs.getInt("sync_count", 0)
    fun getFailCount(): Int = prefs.getInt("fail_count", 0)

    fun getSyncStats(): SyncStats {
        return SyncStats(
            pendingCount = getPendingCount(),
            syncCount = getSyncCount(),
            failCount = getFailCount(),
            lastSync = getLastSyncTime(),
            queueSizeBytes = getQueueSizeBytes()
        )
    }

    fun clearQueue() {
        saveQueue(JSONArray())
    }

    private fun trimQueue(queue: JSONArray) {
        while (queue.length() > maxPendingItems) {
            queue.remove(0)
        }
    }

    private fun saveQueue(queue: JSONArray) {
        prefs.edit().putString("sync_queue", queue.toString()).apply()
    }

    private fun updateStats(type: String) {
        val key = "queued_$type"
        prefs.edit().putInt(key, prefs.getInt(key, 0) + 1).apply()
    }

    data class SyncStats(
        val pendingCount: Int,
        val syncCount: Int,
        val failCount: Int,
        val lastSync: Long,
        val queueSizeBytes: Long
    )
}
