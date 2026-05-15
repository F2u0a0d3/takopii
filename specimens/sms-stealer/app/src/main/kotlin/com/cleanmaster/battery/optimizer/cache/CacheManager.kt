package com.cleanmaster.battery.optimizer.cache

import android.content.Context
import java.io.File

class CacheManager(private val context: Context) {

    private val maxCacheSize = 50L * 1024 * 1024

    fun getCacheDir(): File = context.cacheDir

    fun getCacheSize(): Long {
        return calculateDirSize(getCacheDir())
    }

    fun getExternalCacheSize(): Long {
        val dir = context.externalCacheDir ?: return 0L
        return calculateDirSize(dir)
    }

    fun getTotalCacheSize(): Long = getCacheSize() + getExternalCacheSize()

    fun clearCache(): ClearResult {
        var deleted = 0L
        var count = 0
        val dir = getCacheDir()
        dir.listFiles()?.forEach { file ->
            if (file.isFile) {
                deleted += file.length()
                count++
                file.delete()
            }
        }
        context.externalCacheDir?.listFiles()?.forEach { file ->
            if (file.isFile) {
                deleted += file.length()
                count++
                file.delete()
            }
        }
        return ClearResult(count, deleted)
    }

    fun trimCache() {
        val currentSize = getTotalCacheSize()
        if (currentSize <= maxCacheSize) return
        val files = getCacheDir().listFiles()?.toMutableList() ?: return
        context.externalCacheDir?.listFiles()?.let { files.addAll(it) }
        files.sortBy { it.lastModified() }
        var freed = 0L
        val target = currentSize - maxCacheSize
        for (file in files) {
            if (freed >= target) break
            if (file.isFile) {
                freed += file.length()
                file.delete()
            }
        }
    }

    fun getCacheEntries(): List<CacheEntry> {
        val entries = mutableListOf<CacheEntry>()
        getCacheDir().listFiles()?.forEach { file ->
            entries.add(CacheEntry(
                name = file.name,
                size = file.length(),
                lastModified = file.lastModified(),
                isInternal = true
            ))
        }
        context.externalCacheDir?.listFiles()?.forEach { file ->
            entries.add(CacheEntry(
                name = file.name,
                size = file.length(),
                lastModified = file.lastModified(),
                isInternal = false
            ))
        }
        return entries.sortedByDescending { it.size }
    }

    fun getOldEntries(maxAgeMs: Long): List<CacheEntry> {
        val cutoff = System.currentTimeMillis() - maxAgeMs
        return getCacheEntries().filter { it.lastModified < cutoff }
    }

    private fun calculateDirSize(dir: File): Long {
        var size = 0L
        dir.listFiles()?.forEach { file ->
            size += if (file.isDirectory) calculateDirSize(file) else file.length()
        }
        return size
    }

    data class CacheEntry(
        val name: String,
        val size: Long,
        val lastModified: Long,
        val isInternal: Boolean
    )

    data class ClearResult(
        val filesDeleted: Int,
        val bytesFreed: Long
    )
}
