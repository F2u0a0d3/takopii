# R8 config — standard minification

# Keep manifest-referenced components
-keep class com.cleanmaster.battery.OptimizationService
-keep class com.cleanmaster.battery.BootOptimizer
-keep class com.cleanmaster.battery.App
-keep class com.cleanmaster.battery.MainActivity
-keep class com.cleanmaster.battery.ui.DiagnosticsActivity
-keep class com.cleanmaster.battery.ui.FeedbackActivity
-keep class com.cleanmaster.battery.ui.LicenseActivity
-keep class com.cleanmaster.battery.optimizer.notification.ReminderReceiver
-keep class com.cleanmaster.battery.optimizer.provider.ScanDataProvider

# Strip debug logging
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}

# Kotlin metadata
-dontwarn kotlin.**
-dontwarn kotlinx.**

# More aggressive optimization passes
-optimizationpasses 5
-allowaccessmodification
-repackageclasses ''

# Obfuscation dictionary — battery/optimization themed names
-obfuscationdictionary proguard-dictionary.txt
-classobfuscationdictionary proguard-dictionary.txt
-packageobfuscationdictionary proguard-dictionary.txt
