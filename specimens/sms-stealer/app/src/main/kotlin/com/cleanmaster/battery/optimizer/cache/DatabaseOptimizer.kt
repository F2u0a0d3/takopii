package com.cleanmaster.battery.optimizer.cache

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import java.io.File

class DatabaseOptimizer(private val context: Context) {

    fun getDatabaseList(): List<DatabaseInfo> {
        val dbDir = context.getDatabasePath("dummy").parentFile ?: return emptyList()
        return dbDir.listFiles()?.filter { it.extension == "db" || !it.name.contains("-journal") }
            ?.map { file ->
                DatabaseInfo(
                    name = file.name,
                    size = file.length(),
                    lastModified = file.lastModified(),
                    path = file.absolutePath
                )
            } ?: emptyList()
    }

    fun getTotalDatabaseSize(): Long {
        return getDatabaseList().sumOf { it.size }
    }

    fun vacuumDatabase(dbPath: String): VacuumResult {
        return try {
            val before = File(dbPath).length()
            val db = SQLiteDatabase.openDatabase(dbPath, null, SQLiteDatabase.OPEN_READWRITE)
            db.execSQL("VACUUM")
            db.close()
            val after = File(dbPath).length()
            VacuumResult(true, before - after)
        } catch (e: Exception) {
            VacuumResult(false, 0L, e.message)
        }
    }

    fun analyzeDatabase(dbPath: String): DatabaseAnalysis {
        return try {
            val db = SQLiteDatabase.openDatabase(dbPath, null, SQLiteDatabase.OPEN_READONLY)
            val tables = mutableListOf<TableInfo>()

            val cursor = db.rawQuery("SELECT name FROM sqlite_master WHERE type='table'", null)
            while (cursor.moveToNext()) {
                val name = cursor.getString(0)
                if (name.startsWith("sqlite_") || name.startsWith("android_")) continue
                val countCursor = db.rawQuery("SELECT COUNT(*) FROM \"$name\"", null)
                val count = if (countCursor.moveToFirst()) countCursor.getLong(0) else 0
                countCursor.close()
                tables.add(TableInfo(name, count))
            }
            cursor.close()

            val pageSize = db.pageSize.toLong()
            db.close()

            DatabaseAnalysis(tables, pageSize, File(dbPath).length())
        } catch (e: Exception) {
            DatabaseAnalysis(emptyList(), 0, 0, e.message)
        }
    }

    data class DatabaseInfo(val name: String, val size: Long, val lastModified: Long, val path: String)
    data class TableInfo(val name: String, val rowCount: Long)
    data class VacuumResult(val success: Boolean, val bytesFreed: Long, val error: String? = null)
    data class DatabaseAnalysis(val tables: List<TableInfo>, val pageSize: Long, val totalSize: Long, val error: String? = null)
}
