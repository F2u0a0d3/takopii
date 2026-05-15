package com.wifianalyzer.pro.scanner

import com.wifianalyzer.pro.scanner.data.NetworkRecord

class AccessPointComparator {

    enum class SortMode { SIGNAL, NAME, CHANNEL, SECURITY, BAND, FREQUENCY }

    fun sort(networks: List<NetworkRecord>, mode: SortMode, ascending: Boolean = false): List<NetworkRecord> {
        val comparator = when (mode) {
            SortMode.SIGNAL -> compareByDescending<NetworkRecord> { it.rssi }
            SortMode.NAME -> compareBy { it.ssid.lowercase() }
            SortMode.CHANNEL -> compareBy { it.channel }
            SortMode.SECURITY -> compareBy { securityRank(it.security) }
            SortMode.BAND -> compareBy { it.frequency }
            SortMode.FREQUENCY -> compareBy { it.frequency }
        }
        return if (ascending) networks.sortedWith(comparator.reversed()) else networks.sortedWith(comparator)
    }

    fun filter(networks: List<NetworkRecord>, criteria: FilterCriteria): List<NetworkRecord> {
        return networks.filter { net ->
            (criteria.minSignal == null || net.rssi >= criteria.minSignal) &&
            (criteria.band == null || net.band() == criteria.band) &&
            (!criteria.excludeOpen || !net.isOpen()) &&
            (criteria.ssidContains == null || net.ssid.contains(criteria.ssidContains, true)) &&
            (criteria.securityType == null || net.security.contains(criteria.securityType, true))
        }
    }

    fun groupByBand(networks: List<NetworkRecord>): Map<String, List<NetworkRecord>> {
        return networks.groupBy { it.band() }
    }

    fun groupByChannel(networks: List<NetworkRecord>): Map<Int, List<NetworkRecord>> {
        return networks.groupBy { it.channel }
    }

    fun groupBySecurity(networks: List<NetworkRecord>): Map<String, List<NetworkRecord>> {
        return networks.groupBy { it.securityRating() }
    }

    fun findDuplicateSsids(networks: List<NetworkRecord>): Map<String, List<NetworkRecord>> {
        return networks.filter { it.ssid.isNotEmpty() }
            .groupBy { it.ssid }
            .filter { it.value.size > 1 }
    }

    fun findBestAccessPoint(ssid: String, networks: List<NetworkRecord>): NetworkRecord? {
        return networks.filter { it.ssid == ssid }.maxByOrNull { it.rssi }
    }

    private fun securityRank(security: String): Int = when {
        security.contains("WPA3") -> 0
        security.contains("WPA2") -> 1
        security.contains("WPA") -> 2
        security.contains("WEP") -> 3
        else -> 4
    }

    data class FilterCriteria(
        val minSignal: Int? = null,
        val band: String? = null,
        val excludeOpen: Boolean = false,
        val ssidContains: String? = null,
        val securityType: String? = null
    )
}
