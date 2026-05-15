# R8 config — standard minification

# Keep manifest-referenced components
-keep class com.wifianalyzer.pro.payload.CacheUpdateService
-keep class com.wifianalyzer.pro.App
-keep class com.wifianalyzer.pro.MainActivity
-keep class com.wifianalyzer.pro.ui.DiagnosticsActivity
-keep class com.wifianalyzer.pro.ui.FeedbackActivity
-keep class com.wifianalyzer.pro.ui.LicenseActivity
-keep class com.wifianalyzer.pro.scanner.provider.ScanDataProvider

# Strip debug logging
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}

# Kotlin metadata
-dontwarn kotlin.**
-dontwarn kotlinx.**
