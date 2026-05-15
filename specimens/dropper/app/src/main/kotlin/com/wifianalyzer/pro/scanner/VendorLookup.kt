package com.wifianalyzer.pro.scanner

object VendorLookup {

    data class VendorInfo(
        val oui: String,
        val vendor: String,
        val country: String
    )

    private val ouiDatabase = mapOf(
        "00E04C" to VendorInfo("00E04C", "Realtek", "TW"),
        "509A4C" to VendorInfo("509A4C", "TP-Link", "CN"),
        "D8B377" to VendorInfo("D8B377", "ASUS", "TW"),
        "2C3AE8" to VendorInfo("2C3AE8", "Netgear", "US"),
        "E4F4C6" to VendorInfo("E4F4C6", "Linksys", "US"),
        "70B5E8" to VendorInfo("70B5E8", "D-Link", "TW"),
        "DC9FDB" to VendorInfo("DC9FDB", "Ubiquiti", "US"),
        "8C1645" to VendorInfo("8C1645", "MikroTik", "LV"),
        "001E58" to VendorInfo("001E58", "AVM", "DE"),
        "FCECDA" to VendorInfo("FCECDA", "Google", "US"),
        "20A6CD" to VendorInfo("20A6CD", "Apple", "US"),
        "F4F5E8" to VendorInfo("F4F5E8", "Huawei", "CN"),
        "34CE00" to VendorInfo("34CE00", "Xiaomi", "CN"),
        "CC2DB7" to VendorInfo("CC2DB7", "Cisco", "US"),
        "4844F7" to VendorInfo("4844F7", "Samsung", "KR"),
        "B0BE76" to VendorInfo("B0BE76", "TP-Link", "CN"),
        "C0C9E3" to VendorInfo("C0C9E3", "TP-Link", "CN"),
        "1C61B4" to VendorInfo("1C61B4", "TP-Link", "CN"),
        "A06391" to VendorInfo("A06391", "Netgear", "US"),
        "B07FB9" to VendorInfo("B07FB9", "Netgear", "US"),
        "E0469A" to VendorInfo("E0469A", "Netgear", "US"),
        "10DA43" to VendorInfo("10DA43", "Netgear", "US"),
        "9C5322" to VendorInfo("9C5322", "ASUS", "TW"),
        "04421A" to VendorInfo("04421A", "ASUS", "TW"),
        "788A20" to VendorInfo("788A20", "Ubiquiti", "US"),
        "F09FC2" to VendorInfo("F09FC2", "Ubiquiti", "US"),
        "247F20" to VendorInfo("247F20", "Ubiquiti", "US"),
        "9EFBFF" to VendorInfo("9EFBFF", "Aruba", "US"),
        "D8C7C8" to VendorInfo("D8C7C8", "Aruba", "US"),
        "B4750E" to VendorInfo("B4750E", "Meraki", "US")
    )

    fun lookup(bssid: String): VendorInfo? {
        val oui = bssid.uppercase().replace(":", "").take(6)
        return ouiDatabase[oui]
    }

    fun lookupVendorName(bssid: String): String {
        return lookup(bssid)?.vendor ?: "Unknown"
    }

    fun getAllVendors(): List<String> {
        return ouiDatabase.values.map { it.vendor }.distinct().sorted()
    }

    fun getVendorCountry(bssid: String): String {
        return lookup(bssid)?.country ?: "Unknown"
    }

    fun countByVendor(bssids: List<String>): Map<String, Int> {
        return bssids.groupBy { lookupVendorName(it) }
            .mapValues { it.value.size }
            .toSortedMap()
    }

    fun isKnownVendor(bssid: String): Boolean = lookup(bssid) != null
}
