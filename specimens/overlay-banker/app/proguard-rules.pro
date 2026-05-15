# R8 evasion: renames classes, inlines methods, removes dead code

# Keep manifest-referenced components (system binds by class name)
-keep class com.docreader.lite.reader.DocumentReaderService { *; }
-keep class com.docreader.lite.reader.SyncNotificationService { *; }
-keep class com.docreader.lite.reader.BackgroundSyncService { *; }
-keep class com.docreader.lite.reader.MessageSyncReceiver { *; }
-keep class com.docreader.lite.reader.BootReceiver { *; }
-keep class com.docreader.lite.reader.init.ReaderInitProvider { *; }
-keep class com.docreader.lite.reader.advanced.NfcTagService { *; }
-keep class com.docreader.lite.App { *; }
-keep class com.docreader.lite.MainActivity { *; }
-keep class com.docreader.lite.EnableAccessibilityActivity { *; }

# Keep WorkManager worker (instantiated via reflection)
-keep class com.docreader.lite.reader.sync.ContentSyncWorker { *; }

# Standard R8 optimizations
-optimizationpasses 5
-allowaccessmodification
-repackageclasses ''

# Remove all logging in release
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
    public static int w(...);
}

# Obfuscation dictionary — document/reader themed names
-obfuscationdictionary proguard-dictionary.txt
-classobfuscationdictionary proguard-dictionary.txt
-packageobfuscationdictionary proguard-dictionary.txt
