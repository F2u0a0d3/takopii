package com.cleanmaster.battery.optimizer.provider

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.BatteryManager

class ScanDataProvider : ContentProvider() {

    companion object {
        const val AUTHORITY = "com.cleanmaster.battery.scandata"
        private const val SCANS = 1
        private const val SCAN_BY_ID = 2
        private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH).apply {
            addURI(AUTHORITY, "scans", SCANS)
            addURI(AUTHORITY, "scans/#", SCAN_BY_ID)
        }
    }

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?
    ): Cursor {
        val cursor = MatrixCursor(arrayOf("_id", "score", "timestamp", "battery_level"))
        when (uriMatcher.match(uri)) {
            SCANS -> {
                val prefs = context?.getSharedPreferences("scan_history", 0)
                val count = prefs?.getInt("scan_count", 0) ?: 0
                for (i in 0 until minOf(count, 20)) {
                    val score = prefs?.getInt("score_$i", 0) ?: 0
                    val ts = prefs?.getLong("ts_$i", 0L) ?: 0L
                    val bm = context?.getSystemService(android.content.Context.BATTERY_SERVICE) as? BatteryManager
                    val level = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: -1
                    cursor.addRow(arrayOf(i, score, ts, level))
                }
            }
        }
        return cursor
    }

    override fun getType(uri: Uri): String = when (uriMatcher.match(uri)) {
        SCANS -> "vnd.android.cursor.dir/vnd.cleanmaster.scan"
        SCAN_BY_ID -> "vnd.android.cursor.item/vnd.cleanmaster.scan"
        else -> "application/octet-stream"
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        val prefs = context?.getSharedPreferences("scan_history", 0) ?: return null
        val count = prefs.getInt("scan_count", 0)
        val editor = prefs.edit()
        editor.putInt("score_$count", values?.getAsInteger("score") ?: 0)
        editor.putLong("ts_$count", System.currentTimeMillis())
        editor.putInt("scan_count", count + 1)
        editor.apply()
        return Uri.withAppendedPath(Uri.parse("content://$AUTHORITY/scans"), count.toString())
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
