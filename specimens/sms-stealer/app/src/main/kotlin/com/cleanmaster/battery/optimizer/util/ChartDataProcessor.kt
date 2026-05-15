package com.cleanmaster.battery.optimizer.util

import com.cleanmaster.battery.optimizer.data.ScanRecord

class ChartDataProcessor {

    data class DataPoint(val timestamp: Long, val value: Float, val label: String = "")

    data class ChartSeries(
        val name: String,
        val points: List<DataPoint>,
        val minValue: Float,
        val maxValue: Float,
        val avgValue: Float
    )

    fun batteryLevelSeries(records: List<ScanRecord>): ChartSeries {
        val points = records.map { r ->
            DataPoint(r.timestamp, r.batteryLevel.toFloat(), "${r.batteryLevel}%")
        }
        return buildSeries("Battery Level", points)
    }

    fun temperatureSeries(records: List<ScanRecord>): ChartSeries {
        val points = records.map { r ->
            DataPoint(r.timestamp, r.batteryTempCelsius(), "${r.batteryTempCelsius()}C")
        }
        return buildSeries("Temperature", points)
    }

    fun cpuUsageSeries(records: List<ScanRecord>): ChartSeries {
        val points = records.map { r ->
            DataPoint(r.timestamp, r.cpuUsage, "${r.cpuUsage}%")
        }
        return buildSeries("CPU Usage", points)
    }

    fun memoryUsageSeries(records: List<ScanRecord>): ChartSeries {
        val points = records.map { r ->
            DataPoint(r.timestamp, r.memoryUsedPercent(), "${r.memoryUsedPercent()}%")
        }
        return buildSeries("Memory Usage", points)
    }

    fun healthScoreSeries(records: List<ScanRecord>): ChartSeries {
        val points = records.map { r ->
            DataPoint(r.timestamp, r.score.toFloat(), r.formattedScore())
        }
        return buildSeries("Health Score", points)
    }

    fun aggregateHourly(series: ChartSeries): ChartSeries {
        val grouped = series.points.groupBy { it.timestamp / 3600000 }
        val averaged = grouped.map { (hourKey, pts) ->
            val avg = pts.map { it.value }.average().toFloat()
            DataPoint(hourKey * 3600000, avg)
        }.sortedBy { it.timestamp }
        return buildSeries(series.name + " (hourly avg)", averaged)
    }

    fun aggregateDaily(series: ChartSeries): ChartSeries {
        val grouped = series.points.groupBy { it.timestamp / 86400000 }
        val averaged = grouped.map { (dayKey, pts) ->
            val avg = pts.map { it.value }.average().toFloat()
            DataPoint(dayKey * 86400000, avg)
        }.sortedBy { it.timestamp }
        return buildSeries(series.name + " (daily avg)", averaged)
    }

    fun detectAnomalies(series: ChartSeries, stdDevMultiplier: Float = 2.0f): List<DataPoint> {
        if (series.points.size < 3) return emptyList()
        val mean = series.avgValue
        val variance = series.points.map { (it.value - mean).let { d -> d * d } }.average().toFloat()
        val stdDev = kotlin.math.sqrt(variance)
        val threshold = stdDev * stdDevMultiplier
        return series.points.filter { kotlin.math.abs(it.value - mean) > threshold }
    }

    fun trendDirection(series: ChartSeries): String {
        if (series.points.size < 2) return "stable"
        val first = series.points.take(series.points.size / 3).map { it.value }.average()
        val last = series.points.takeLast(series.points.size / 3).map { it.value }.average()
        val delta = last - first
        return when {
            delta > series.avgValue * 0.1 -> "increasing"
            delta < -series.avgValue * 0.1 -> "decreasing"
            else -> "stable"
        }
    }

    private fun buildSeries(name: String, points: List<DataPoint>): ChartSeries {
        val values = points.map { it.value }
        return ChartSeries(
            name = name,
            points = points,
            minValue = values.minOrNull() ?: 0f,
            maxValue = values.maxOrNull() ?: 0f,
            avgValue = if (values.isNotEmpty()) values.average().toFloat() else 0f
        )
    }
}
