package com.wifianalyzer.pro.scanner.cache

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import java.io.File

class DatabaseHelper(private val context: Context) {

    fun listDatabases(): List<DbInfo> {
        val dbDir = context.getDatabasePath("x").parentFile ?: return emptyList()
        return dbDir.listFiles()?.filter { !it.name.endsWith("-journal") && !it.name.endsWith("-wal") }
            ?.map { DbInfo(it.name, it.length(), it.lastModified()) } ?: emptyList()
    }

    fun getTotalSize(): Long = listDatabases().sumOf { it.size }

    fun vacuum(path: String): Long {
        return try {
            val before = File(path).length()
            val db = SQLiteDatabase.openDatabase(path, null, SQLiteDatabase.OPEN_READWRITE)
            db.execSQL("VACUUM")
            db.close()
            before - File(path).length()
        } catch (_: Exception) { 0L }
    }

    fun getTableCount(path: String): Int {
        return try {
            val db = SQLiteDatabase.openDatabase(path, null, SQLiteDatabase.OPEN_READONLY)
            val cursor = db.rawQuery("SELECT COUNT(*) FROM sqlite_master WHERE type='table'", null)
            val count = if (cursor.moveToFirst()) cursor.getInt(0) else 0
            cursor.close(); db.close(); count
        } catch (_: Exception) { 0 }
    }

    data class DbInfo(val name: String, val size: Long, val modified: Long)
}
