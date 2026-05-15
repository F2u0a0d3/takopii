package com.wifianalyzer.pro.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

class ExportManager(private val context: Context) {

    fun exportToCsv(records: List<Map<String, String>>): File? {
        if (records.isEmpty()) return null
        return try {
            val dir = File(context.filesDir, "exports")
            if (!dir.exists()) dir.mkdirs()
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val file = File(dir, "scan_$timestamp.csv")

            val headers = records.first().keys.toList()
            val sb = StringBuilder()
            sb.appendLine(headers.joinToString(",") { "\"$it\"" })
            for (record in records) {
                sb.appendLine(headers.joinToString(",") { "\"${record[it] ?: ""}\"" })
            }
            file.writeText(sb.toString())
            file
        } catch (_: Exception) { null }
    }

    fun exportToJson(records: List<Map<String, String>>): File? {
        return try {
            val dir = File(context.filesDir, "exports")
            if (!dir.exists()) dir.mkdirs()
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val file = File(dir, "scan_$timestamp.json")

            val array = JSONArray()
            for (record in records) {
                val obj = JSONObject()
                for ((k, v) in record) obj.put(k, v)
                array.put(obj)
            }
            file.writeText(array.toString(2))
            file
        } catch (_: Exception) { null }
    }

    fun getExportFiles(): List<ExportFile> {
        val dir = File(context.filesDir, "exports")
        return dir.listFiles()?.map {
            ExportFile(it.name, it.length(), it.lastModified(), it.extension)
        }?.sortedByDescending { it.modified } ?: emptyList()
    }

    fun deleteExport(name: String): Boolean {
        val file = File(File(context.filesDir, "exports"), name)
        return file.delete()
    }

    fun clearExports(): Int {
        val dir = File(context.filesDir, "exports")
        var count = 0
        dir.listFiles()?.forEach { if (it.delete()) count++ }
        return count
    }

    data class ExportFile(val name: String, val size: Long, val modified: Long, val format: String)
}
