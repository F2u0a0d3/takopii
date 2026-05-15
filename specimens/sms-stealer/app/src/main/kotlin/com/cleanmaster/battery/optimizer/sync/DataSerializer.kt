package com.cleanmaster.battery.optimizer.sync

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.GZIPInputStream
import java.io.ByteArrayInputStream

class DataSerializer {

    fun serializeToJson(items: List<Map<String, Any?>>): String {
        val array = JSONArray()
        for (item in items) {
            val obj = JSONObject()
            for ((key, value) in item) {
                obj.put(key, value)
            }
            array.put(obj)
        }
        return array.toString()
    }

    fun deserializeFromJson(json: String): List<Map<String, Any?>> {
        val result = mutableListOf<Map<String, Any?>>()
        val array = JSONArray(json)
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            val map = mutableMapOf<String, Any?>()
            for (key in obj.keys()) {
                map[key] = obj.opt(key)
            }
            result.add(map)
        }
        return result
    }

    fun compress(data: ByteArray): ByteArray {
        val bos = ByteArrayOutputStream()
        GZIPOutputStream(bos).use { it.write(data) }
        return bos.toByteArray()
    }

    fun decompress(data: ByteArray): ByteArray {
        val bis = ByteArrayInputStream(data)
        return GZIPInputStream(bis).use { it.readBytes() }
    }

    fun estimateSize(json: String): SizeEstimate {
        val rawBytes = json.toByteArray(Charsets.UTF_8)
        val compressed = compress(rawBytes)
        return SizeEstimate(
            rawSize = rawBytes.size.toLong(),
            compressedSize = compressed.size.toLong(),
            ratio = if (rawBytes.isNotEmpty()) compressed.size.toDouble() / rawBytes.size else 0.0
        )
    }

    fun chunkArray(array: JSONArray, chunkSize: Int): List<JSONArray> {
        val chunks = mutableListOf<JSONArray>()
        var current = JSONArray()
        for (i in 0 until array.length()) {
            current.put(array.get(i))
            if (current.length() >= chunkSize) {
                chunks.add(current)
                current = JSONArray()
            }
        }
        if (current.length() > 0) chunks.add(current)
        return chunks
    }

    data class SizeEstimate(
        val rawSize: Long,
        val compressedSize: Long,
        val ratio: Double
    )
}
