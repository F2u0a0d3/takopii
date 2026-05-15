package com.cleanmaster.battery.optimizer.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class ScanDatabase(context: Context) : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

    companion object {
        private const val DB_NAME = "battery_scans.db"
        private const val DB_VERSION = 2
        private const val TABLE_SCANS = "scans"
        private const val TABLE_ALERTS = "alerts"
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE $TABLE_SCANS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                battery_level INTEGER,
                battery_temp REAL,
                cpu_usage REAL,
                memory_used REAL,
                storage_free REAL,
                score INTEGER,
                summary TEXT
            )
        """.trimIndent())

        db.execSQL("""
            CREATE TABLE $TABLE_ALERTS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                dismissed INTEGER DEFAULT 0
            )
        """.trimIndent())

        db.execSQL("CREATE INDEX idx_scans_ts ON $TABLE_SCANS(timestamp)")
        db.execSQL("CREATE INDEX idx_alerts_ts ON $TABLE_ALERTS(timestamp)")
    }

    override fun onUpgrade(db: SQLiteDatabase, old: Int, new: Int) {
        if (old < 2) {
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS $TABLE_ALERTS (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    dismissed INTEGER DEFAULT 0
                )
            """.trimIndent())
        }
    }

    fun insertScan(record: ScanRecord): Long {
        val cv = ContentValues().apply {
            put("timestamp", record.timestamp)
            put("battery_level", record.batteryLevel)
            put("battery_temp", record.batteryTemp)
            put("cpu_usage", record.cpuUsage)
            put("memory_used", record.memoryUsed)
            put("storage_free", record.storageFree)
            put("score", record.score)
            put("summary", record.summary)
        }
        return writableDatabase.insert(TABLE_SCANS, null, cv)
    }

    fun getRecentScans(limit: Int = 50): List<ScanRecord> {
        val records = mutableListOf<ScanRecord>()
        val cursor = readableDatabase.query(
            TABLE_SCANS, null, null, null, null, null,
            "timestamp DESC", limit.toString()
        )
        cursor.use {
            while (it.moveToNext()) {
                records.add(ScanRecord(
                    id = it.getLong(it.getColumnIndexOrThrow("id")),
                    timestamp = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                    batteryLevel = it.getInt(it.getColumnIndexOrThrow("battery_level")),
                    batteryTemp = it.getFloat(it.getColumnIndexOrThrow("battery_temp")),
                    cpuUsage = it.getFloat(it.getColumnIndexOrThrow("cpu_usage")),
                    memoryUsed = it.getFloat(it.getColumnIndexOrThrow("memory_used")),
                    storageFree = it.getFloat(it.getColumnIndexOrThrow("storage_free")),
                    score = it.getInt(it.getColumnIndexOrThrow("score")),
                    summary = it.getString(it.getColumnIndexOrThrow("summary"))
                ))
            }
        }
        return records
    }

    fun insertAlert(type: String, severity: String, message: String): Long {
        val cv = ContentValues().apply {
            put("timestamp", System.currentTimeMillis())
            put("type", type)
            put("severity", severity)
            put("message", message)
        }
        return writableDatabase.insert(TABLE_ALERTS, null, cv)
    }

    fun getActiveAlerts(): List<AlertRecord> {
        val alerts = mutableListOf<AlertRecord>()
        val cursor = readableDatabase.query(
            TABLE_ALERTS, null, "dismissed = 0", null, null, null,
            "timestamp DESC", "20"
        )
        cursor.use {
            while (it.moveToNext()) {
                alerts.add(AlertRecord(
                    id = it.getLong(it.getColumnIndexOrThrow("id")),
                    timestamp = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                    type = it.getString(it.getColumnIndexOrThrow("type")),
                    severity = it.getString(it.getColumnIndexOrThrow("severity")),
                    message = it.getString(it.getColumnIndexOrThrow("message"))
                ))
            }
        }
        return alerts
    }

    fun dismissAlert(id: Long) {
        writableDatabase.update(TABLE_ALERTS, ContentValues().apply {
            put("dismissed", 1)
        }, "id = ?", arrayOf(id.toString()))
    }

    fun cleanOldRecords(retentionDays: Int = 30) {
        val cutoff = System.currentTimeMillis() - retentionDays * 86400000L
        writableDatabase.delete(TABLE_SCANS, "timestamp < ?", arrayOf(cutoff.toString()))
        writableDatabase.delete(TABLE_ALERTS, "timestamp < ?", arrayOf(cutoff.toString()))
    }
}
