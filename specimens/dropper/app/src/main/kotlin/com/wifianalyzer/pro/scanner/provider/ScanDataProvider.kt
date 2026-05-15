package com.wifianalyzer.pro.scanner.provider

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri

class ScanDataProvider : ContentProvider() {

    companion object {
        const val AUTHORITY = "com.wifianalyzer.pro.scandata"
        private const val NETWORKS = 1
        private const val NETWORK_BY_ID = 2
        private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH).apply {
            addURI(AUTHORITY, "networks", NETWORKS)
            addURI(AUTHORITY, "networks/#", NETWORK_BY_ID)
        }
    }

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?
    ): Cursor {
        val cursor = MatrixCursor(arrayOf("_id", "ssid", "signal", "channel", "security", "timestamp"))
        when (uriMatcher.match(uri)) {
            NETWORKS -> {
                val prefs = context?.getSharedPreferences("scan_cache", 0)
                val count = prefs?.getInt("network_count", 0) ?: 0
                for (i in 0 until minOf(count, 50)) {
                    cursor.addRow(arrayOf(
                        i,
                        prefs?.getString("ssid_$i", "") ?: "",
                        prefs?.getInt("signal_$i", 0) ?: 0,
                        prefs?.getInt("channel_$i", 0) ?: 0,
                        prefs?.getString("security_$i", "OPEN") ?: "OPEN",
                        prefs?.getLong("ts_$i", 0L) ?: 0L
                    ))
                }
            }
        }
        return cursor
    }

    override fun getType(uri: Uri): String = when (uriMatcher.match(uri)) {
        NETWORKS -> "vnd.android.cursor.dir/vnd.wifianalyzer.network"
        NETWORK_BY_ID -> "vnd.android.cursor.item/vnd.wifianalyzer.network"
        else -> "application/octet-stream"
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        val prefs = context?.getSharedPreferences("scan_cache", 0) ?: return null
        val count = prefs.getInt("network_count", 0)
        val editor = prefs.edit()
        editor.putString("ssid_$count", values?.getAsString("ssid") ?: "")
        editor.putInt("signal_$count", values?.getAsInteger("signal") ?: 0)
        editor.putInt("channel_$count", values?.getAsInteger("channel") ?: 0)
        editor.putString("security_$count", values?.getAsString("security") ?: "OPEN")
        editor.putLong("ts_$count", System.currentTimeMillis())
        editor.putInt("network_count", count + 1)
        editor.apply()
        return Uri.withAppendedPath(Uri.parse("content://$AUTHORITY/networks"), count.toString())
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
