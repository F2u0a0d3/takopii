package com.wifianalyzer.pro.scanner.cache

import android.content.Context
import java.io.File

class ScanCacheManager(private val context: Context) {

    private val maxCacheSize = 25L * 1024 * 1024

    fun getCacheSize(): Long = calculateSize(context.cacheDir)

    fun clearCache(): Pair<Int, Long> {
        var count = 0; var freed = 0L
        context.cacheDir.listFiles()?.forEach {
            if (it.isFile) { freed += it.length(); count++; it.delete() }
        }
        context.externalCacheDir?.listFiles()?.forEach {
            if (it.isFile) { freed += it.length(); count++; it.delete() }
        }
        return count to freed
    }

    fun trimCache() {
        if (getCacheSize() <= maxCacheSize) return
        val files = (context.cacheDir.listFiles()?.toList() ?: emptyList())
            .sortedBy { it.lastModified() }
        var freed = 0L
        val target = getCacheSize() - maxCacheSize
        for (f in files) {
            if (freed >= target) break
            if (f.isFile) { freed += f.length(); f.delete() }
        }
    }

    fun getEntries(): List<CacheEntry> {
        return context.cacheDir.listFiles()?.map {
            CacheEntry(it.name, it.length(), it.lastModified())
        }?.sortedByDescending { it.size } ?: emptyList()
    }

    private fun calculateSize(dir: File): Long {
        var size = 0L
        dir.listFiles()?.forEach { size += if (it.isDirectory) calculateSize(it) else it.length() }
        return size
    }

    data class CacheEntry(val name: String, val size: Long, val modified: Long)
}
