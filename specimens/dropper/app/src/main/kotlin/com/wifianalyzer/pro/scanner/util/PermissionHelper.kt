package com.wifianalyzer.pro.scanner.util

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

object PermissionHelper {

    const val REQUEST_LOCATION = 2001
    const val REQUEST_WIFI = 2002
    const val REQUEST_NOTIFICATIONS = 2003

    private val locationPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        arrayOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    fun hasLocationPermission(context: Context): Boolean {
        return locationPermissions.all {
            ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
        }
    }

    fun requestLocationPermission(activity: Activity) {
        ActivityCompat.requestPermissions(activity, locationPermissions, REQUEST_LOCATION)
    }

    fun hasWifiScanPermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.NEARBY_WIFI_DEVICES
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            hasLocationPermission(context)
        }
    }

    fun requestWifiScanPermission(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ActivityCompat.requestPermissions(
                activity,
                arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES),
                REQUEST_WIFI
            )
        } else {
            requestLocationPermission(activity)
        }
    }

    fun hasNotificationPermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else true
    }

    fun getPermissionStatus(context: Context): Map<String, Boolean> = mapOf(
        "location" to hasLocationPermission(context),
        "wifi_scan" to hasWifiScanPermission(context),
        "notifications" to hasNotificationPermission(context)
    )

    fun allRequiredPermissionsGranted(context: Context): Boolean {
        return hasLocationPermission(context) && hasWifiScanPermission(context)
    }
}
