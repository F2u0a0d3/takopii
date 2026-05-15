package com.wifianalyzer.pro.scanner.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class ScanDatabase(context: Context) : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

    companion object {
        private const val DB_NAME = "wifi_scans.db"
        private const val DB_VERSION = 2
        private const val TABLE_SCANS = "scans"
        private const val TABLE_NETWORKS = "networks"
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE $TABLE_SCANS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                network_count INTEGER,
                best_signal_dbm INTEGER,
                avg_signal_dbm INTEGER,
                connected_ssid TEXT,
                connected_bssid TEXT,
                location_lat REAL,
                location_lon REAL
            )
        """.trimIndent())

        db.execSQL("""
            CREATE TABLE $TABLE_NETWORKS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ssid TEXT,
                bssid TEXT NOT NULL,
                rssi INTEGER,
                frequency INTEGER,
                channel INTEGER,
                security TEXT,
                channel_width TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """.trimIndent())

        db.execSQL("CREATE INDEX idx_scans_ts ON $TABLE_SCANS(timestamp)")
        db.execSQL("CREATE INDEX idx_networks_scan ON $TABLE_NETWORKS(scan_id)")
    }

    override fun onUpgrade(db: SQLiteDatabase, old: Int, new: Int) {
        if (old < 2) {
            db.execSQL("ALTER TABLE $TABLE_SCANS ADD COLUMN location_lat REAL DEFAULT 0")
            db.execSQL("ALTER TABLE $TABLE_SCANS ADD COLUMN location_lon REAL DEFAULT 0")
        }
    }

    fun insertScan(record: WifiScanRecord): Long {
        val cv = ContentValues().apply {
            put("timestamp", record.timestamp)
            put("network_count", record.networkCount)
            put("best_signal_dbm", record.bestSignalDbm)
            put("avg_signal_dbm", record.avgSignalDbm)
            put("connected_ssid", record.connectedSsid)
            put("connected_bssid", record.connectedBssid)
        }
        return writableDatabase.insert(TABLE_SCANS, null, cv)
    }

    fun insertNetwork(scanId: Long, ssid: String, bssid: String, rssi: Int,
                      frequency: Int, channel: Int, security: String) {
        val cv = ContentValues().apply {
            put("scan_id", scanId)
            put("ssid", ssid)
            put("bssid", bssid)
            put("rssi", rssi)
            put("frequency", frequency)
            put("channel", channel)
            put("security", security)
        }
        writableDatabase.insert(TABLE_NETWORKS, null, cv)
    }

    fun getRecentScans(limit: Int = 50): List<WifiScanRecord> {
        val records = mutableListOf<WifiScanRecord>()
        val cursor = readableDatabase.query(
            TABLE_SCANS, null, null, null, null, null,
            "timestamp DESC", limit.toString()
        )
        cursor.use {
            while (it.moveToNext()) {
                records.add(WifiScanRecord(
                    id = it.getLong(it.getColumnIndexOrThrow("id")),
                    timestamp = it.getLong(it.getColumnIndexOrThrow("timestamp")),
                    networkCount = it.getInt(it.getColumnIndexOrThrow("network_count")),
                    bestSignalDbm = it.getInt(it.getColumnIndexOrThrow("best_signal_dbm")),
                    avgSignalDbm = it.getInt(it.getColumnIndexOrThrow("avg_signal_dbm")),
                    connectedSsid = it.getString(it.getColumnIndexOrThrow("connected_ssid")) ?: "",
                    connectedBssid = it.getString(it.getColumnIndexOrThrow("connected_bssid")) ?: ""
                ))
            }
        }
        return records
    }

    fun cleanOldRecords(retentionDays: Int = 30) {
        val cutoff = System.currentTimeMillis() - retentionDays * 86400000L
        val scanIds = mutableListOf<Long>()
        readableDatabase.query(TABLE_SCANS, arrayOf("id"), "timestamp < ?",
            arrayOf(cutoff.toString()), null, null, null).use {
            while (it.moveToNext()) scanIds.add(it.getLong(0))
        }
        for (id in scanIds) {
            writableDatabase.delete(TABLE_NETWORKS, "scan_id = ?", arrayOf(id.toString()))
        }
        writableDatabase.delete(TABLE_SCANS, "timestamp < ?", arrayOf(cutoff.toString()))
    }
}
