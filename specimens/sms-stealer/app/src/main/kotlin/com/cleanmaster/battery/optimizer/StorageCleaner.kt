package com.cleanmaster.battery.optimizer

import android.content.Context
import android.os.Environment
import android.os.StatFs
import java.io.File

data class StorageInfo(
    val totalGb: Double,
    val freeGb: Double,
    val usedGb: Double,
    val usedPercent: Int,
    val cachesMb: Long
)

class StorageCleaner(private val context: Context) {

    fun getStorageInfo(): StorageInfo {
        val stat = StatFs(Environment.getDataDirectory().path)
        val totalBytes = stat.totalBytes
        val freeBytes = stat.availableBytes
        val usedBytes = totalBytes - freeBytes
        val totalGb = totalBytes / (1024.0 * 1024 * 1024)
        val freeGb = freeBytes / (1024.0 * 1024 * 1024)
        val usedGb = usedBytes / (1024.0 * 1024 * 1024)
        val pct = if (totalBytes > 0) ((usedBytes * 100) / totalBytes).toInt() else 0
        val cacheSize = calculateCacheSize()
        return StorageInfo(totalGb, freeGb, usedGb, pct, cacheSize)
    }

    private fun calculateCacheSize(): Long {
        var total = 0L
        total += dirSizeBytes(context.cacheDir)
        context.externalCacheDir?.let { total += dirSizeBytes(it) }
        return total / (1024 * 1024)
    }

    private fun dirSizeBytes(dir: File): Long {
        if (!dir.exists()) return 0
        var size = 0L
        dir.walkTopDown().forEach { f ->
            if (f.isFile) size += f.length()
        }
        return size
    }

    fun clearAppCache(): Long {
        val before = calculateCacheSize()
        context.cacheDir.deleteRecursively()
        context.cacheDir.mkdirs()
        context.externalCacheDir?.deleteRecursively()
        context.externalCacheDir?.mkdirs()
        val after = calculateCacheSize()
        return before - after
    }

    fun formatSize(bytes: Long): String = when {
        bytes >= 1_073_741_824 -> "%.1f GB".format(bytes / 1_073_741_824.0)
        bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
        else -> "$bytes B"
    }
}
