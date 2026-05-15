package com.skyweather.forecast.model

/**
 * City entry for search and display.
 */
data class City(
    val name: String,
    val country: String,
    val lat: Double,
    val lon: Double
) {
    fun displayName(): String = "$name, $country"

    fun matches(query: String): Boolean {
        val q = query.lowercase().trim()
        return name.lowercase().contains(q) || country.lowercase().contains(q)
    }
}

/**
 * Hardcoded city database — sufficient for a functional weather app demo.
 * Real apps use a geocoding API; we use static data to avoid network dependency
 * in the benign layer (design constraint: fewer network calls = smaller attack surface footprint).
 */
object CityDatabase {
    val cities = listOf(
        City("New York", "US", 40.7128, -74.0060),
        City("London", "UK", 51.5074, -0.1278),
        City("Tokyo", "JP", 35.6762, 139.6503),
        City("Paris", "FR", 48.8566, 2.3522),
        City("Sydney", "AU", -33.8688, 151.2093),
        City("Dubai", "AE", 25.2048, 55.2708),
        City("Toronto", "CA", 43.6532, -79.3832),
        City("Berlin", "DE", 52.5200, 13.4050),
        City("Mumbai", "IN", 19.0760, 72.8777),
        City("Seoul", "KR", 37.5665, 126.9780),
        City("Mexico City", "MX", 19.4326, -99.1332),
        City("Cairo", "EG", 30.0444, 31.2357),
        City("Moscow", "RU", 55.7558, 37.6173),
        City("Bangkok", "TH", 13.7563, 100.5018),
        City("Istanbul", "TR", 41.0082, 28.9784),
        City("Buenos Aires", "AR", -34.6037, -58.3816),
        City("Lagos", "NG", 6.5244, 3.3792),
        City("Shanghai", "CN", 31.2304, 121.4737),
        City("Rome", "IT", 41.9028, 12.4964),
        City("Nairobi", "KE", -1.2921, 36.8219)
    )

    fun search(query: String): List<City> {
        if (query.isBlank()) return cities
        return cities.filter { it.matches(query) }
    }
}
