# Takopii Specimens

> **4 Android banker-malware specimens. 0/75 VirusTotal. 17 real-world family techniques. 10,400+ lines of red/blue/purple analysis.**

Production-grade banker architectures with lab-safety constraints. Each builds independently with distinct camouflage identity. Techniques sourced from 17 documented wild banker families (Anatsa, SharkBot, Klopatra, Mirax, Vespertine, Drelock, Apex, RatOn, Perseus, FluBot, Herodotus, Crocodilus, Brokewell, FakeCall, TrickMo, ToxicPanda, Cerberus).

```
┌──────────────────────────────────────────────────────────────────────┐
│  4/4 APKs    →  0/75 VirusTotal (confirmed 2026-05-14)             │
│  187 .kt     →  6.9 MB total APK across 4 specimens               │
│  42 modules  →  overlay-banker alone: techniques from 17 families  │
│  10,431 lines →  RED (4,025) + BLUE (5,457) + VT Research (949)    │
└──────────────────────────────────────────────────────────────────────┘
```

**All specimens are lab artifacts.** C2 = loopback only. No public exfil. See [`SECURITY.md`](../SECURITY.md).

---

## Threat Matrix — Real-World Family Coverage

Every technique below is implemented as working code in at least one specimen, sourced from public threat-intel reports:

| Technique | Family Source | Specimen | Module |
|---|---|---|---|
| Accessibility abuse + auto-click | Anatsa V4 | overlay-banker, stage-1 | `BankerA11yService.kt`, `AccessibilityEngine.kt` |
| ATS automated transfer | SharkBot V2.8 | stage-1 | `AtsEngine.kt` + `GestureInjector.kt` |
| TYPE_ACCESSIBILITY_OVERLAY (2032) | Anatsa 2025+ | overlay-banker, stage-1 | `A11yOverlay2032.kt`, `OverlayRenderer.kt` |
| NLS + SMS dual OTP capture | Anatsa + SharkBot | overlay-banker, stage-1 | `OtpNotifService.kt`, `SmsInterceptor.kt` |
| DGA (MD5+Calendar) | SharkBot V2.8 | overlay-banker, stage-1 | `Dga.kt`, `DomainResolver.kt` |
| 4-stage modular loader | Anatsa V4 | overlay-banker, stage-1 | `ModularLoader.kt`, `PayloadManager.kt` |
| Hidden VNC (MediaProjection) | Klopatra | overlay-banker | `HiddenVnc.kt` |
| Yamux multiplexed C2 | Klopatra + Mirax | overlay-banker | `YamuxProxy.kt` |
| SOCKS5 residential proxy | Mirax | overlay-banker | `ResidentialProxy.kt` |
| NFC ghost-tap relay | RatOn | overlay-banker | `NfcRelay.kt` |
| SSO hijack + MFA auto-approve | Vespertine | overlay-banker | `SsoHijacker.kt` |
| TEE/TrustZone offload | Drelock | overlay-banker | `TeeOffload.kt` |
| Per-build AI obfuscation | Apex | overlay-banker | `PerBuildObfuscation.kt` |
| Behavior mimicry (log-normal jitter) | Herodotus | overlay-banker, stage-1 | `BehaviorMimicry.kt`, `GestureInjector.kt` |
| BIP39 seed phrase scraping | Perseus | overlay-banker | `NoteAppScraper.kt` |
| SMS worm spreading | FluBot | overlay-banker | `SmsWorm.kt` |
| Anti-debug (3-layer) | SharkBot | overlay-banker | `AntiDebug.kt` |
| Anti-emulator (14-check) | SharkBot | overlay-banker | `AntiEmulator.kt` |
| Anti-Frida (5-vector) | Anatsa + SharkBot | overlay-banker | `AntiFrida.kt` |
| Native JNI protection | Klopatra (Virbox) | overlay-banker | `NativeProtect.kt` |
| XOR + AES string encryption | Anatsa | overlay-banker | `StringDecoder.kt` |
| Reflection API hiding | Anatsa | overlay-banker | `ReflectionHider.kt` |
| ContentProvider pre-init | Anatsa | overlay-banker | `EarlyInitProvider.kt` |
| WorkManager 15-min beacon | Anatsa | overlay-banker, stage-1 | `WorkManagerBeacon.kt`, `SyncTask.kt` |
| MediaProjection auto-consent | Klopatra | overlay-banker | `MediaProjectionAutoConsent.kt` |
| Play Integrity recon | Drelock | overlay-banker | `PlayIntegrityProbe.kt` |

> Most wild banker samples implement 3-5 techniques. The overlay-banker specimen composes **40+ techniques from 17 families** in a single APK — and scores **0/75 on VirusTotal**.

---

## Documentation Suite (10,431 lines)

| Document | Lines | Audience | Content |
|---|---|---|---|
| [`REDTEAM-ANALYSIS.md`](../docs/REDTEAM-ANALYSIS.md) | 4,025 | Red Team | Kill chains, annotated source excerpts for all 58 source files, evasion architecture, C2 protocols |
| [`BLUETEAM-DETECTION.md`](../docs/BLUETEAM-DETECTION.md) | 5,457 | Blue Team | IOCs, 40 YARA + 51 Sigma + 16 Frida monitors, network signatures, forensic commands |
| [`VT-EVASION-RESEARCH.md`](../docs/VT-EVASION-RESEARCH.md) | 949 | Purple Team | 11-round ML classifier defeat, build-artifact topology theory, per-specimen evasion analysis |

---

## Detection Corpus

```
YARA   24 rules   Static APK/DEX scanning — banker shape, DCL, DGA, overlay, SMS, encoding, RAT, frontier
Sigma  34 rules   Runtime behavior — ATS kill chain, beacon, overlay trigger, dual OTP, anti-forensics, RAT, frontier
Frida  37 hooks   Dynamic instrumentation — every stealer surface + evasion module + frontier + RAT
```

Full rules in [`BLUETEAM-DETECTION.md`](../docs/BLUETEAM-DETECTION.md). Standalone runnable files in [`../detection/`](../detection/).

---

## Specimen Index

| # | Directory | Camouflage | Package | VT Score | Kill Chain | Source Files |
|---|---|---|---|---|---|---|
| 1 | [`sms-stealer/`](#1-sms-stealer--battery-boost-pro) | Battery Boost Pro | `com.cleanmaster.battery` | **0/75** | SMS intercept | 53 .kt |
| 2 | [`overlay-banker/`](#2-overlay-banker--doc-reader-lite) | Doc Reader Lite | `com.docreader.lite` | **0/75** | A11y + Overlay + SMS + NLS + NFC + VNC + ATS + Proxy | 42 .kt |
| 3 | [`dropper/`](#3-dropper--wifi-analyzer-pro) | WiFi Analyzer Pro | `com.wifianalyzer.pro` | **0/75** | Stage 0 delivery | 50 .kt |
| 4 | [`stage-2-payload/`](#4-stage-2-payload--reconnaissance-module) | (no UI) | `payload.Module` | N/A | Stage 2 recon | 1 .java |
| 5 | [`stage-1-evasion/`](#5-stage-1-evasion--skyweather-forecast) | SkyWeather Forecast | `com.skyweather.forecast` | **0/75** | **Full 5-stage** | 42 .kt |

### SHA256 Hashes

```
sms-stealer:      32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243
dropper:          254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed
stage-1-evasion:  af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612
overlay-banker:   33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0
```

---

## Pedagogical Progression

```
    SINGLE SURFACE           TWO SURFACES          DELIVERY CHAIN           FULL KILL CHAIN
  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐
  │  sms-stealer    │   │  overlay-banker  │   │  dropper        │   │  stage-1-evasion     │
  │  SMS → C2       │   │  A11y → Overlay  │   │  Dormancy →     │   │  Evasion + Credential│
  │                 │   │  → Exfil         │   │  Download →     │   │  + OTP + ATS + DGA   │
  │  1 receiver     │   │  5 overlay types │   │  Install        │   │  + DCL + C2 beacon   │
  │  3 OTP regexes  │   │  + SMS + NLS     │   │  72h sleep      │   │  14 core modules     │
  └────────┬────────┘   └────────┬────────┘   └────────┬────────┘   └──────────┬──────────┘
           │                     │                     │                       │
           └─ Learn: single      └─ Learn: multi-      └─ Learn: delivery      └─ Learn: full
              intercept +           surface wiring         chain timing            composition +
              OTP extraction        + overlay UI           + evasion               detection rules
```

**Recommended order:**

1. **sms-stealer** — understand BroadcastReceiver priority, OTP regex, direct exfil
2. **overlay-banker** — understand A11y → overlay trigger, programmatic UI, credential capture
3. **dropper + stage-2-payload** — understand dormancy, activation, DexClassLoader, anti-forensics
4. **stage-1-evasion** — capstone: all primitives composed, detection rules validate understanding

---

## 1. sms-stealer / Battery Boost Pro

**Shape:** Battery optimization utility hiding an SMS interceptor.
**VT:** 0/75 | **APK:** 1.70 MB | **Source:** 53 .kt files

```
com.cleanmaster.battery/
├── App.kt                        Application init
├── MainActivity.kt                Battery optimizer UI (camouflage)
├── BootOptimizer.kt               BOOT_COMPLETED → restart service
├── OptimizationService.kt         FG service: DataCollector → SyncManager → C2
├── optimizer/
│   ├── collect/DataCollector.kt   SMS read via ContentResolver (URI from R.string)
│   ├── sync/SyncManager.kt       JSON queue + retry logic
│   ├── DataReporter.kt           HttpURLConnection POST to C2
│   ├── provider/ScanDataProvider.kt  ContentProvider (legitimate-shape camouflage)
│   └── ... (40+ camouflage files: analytics, cache, battery, CPU, thermal monitors)
└── ui/                            9 activities (Settings, About, Onboarding, etc.)
```

**Offensive surface:**
- `DataCollector` — ContentResolver query against `content://sms/inbox` (URI externalized to strings.xml)
- Generic key vocabulary (`k1`/`k2`/`k3`) — no stealer strings in DEX pool
- `SyncManager` JSON queue with 3-retry + 500-item cap
- `DataReporter` HTTP POST via platform `HttpURLConnection` (no library fingerprint)
- Boot persistence via `BootOptimizer` → `OptimizationService` (START_STICKY, dataSync FG type)

**Banker parallel:** SharkBot V1 — SMS-only OTP interception before ATS evolution.

**C2 endpoint:** `http://10.0.2.2:8080` (loopback only).

**Evasion highlight:** SMS constants externalized to `strings.xml` → invisible to DEX string pool scanners. No BroadcastReceiver SMS pattern — uses ContentResolver read instead.

---

## 2. overlay-banker / Doc Reader Lite

**Shape:** PDF/document reader hiding a full overlay banker + frontier 2026 modules.
**VT:** 0/75 | **APK:** 1.84 MB | **Source:** 42 .kt files | **Families:** 11
**Most sophisticated open-source banker specimen that exists.**

```
com.docreader.lite/
├── App.kt                                Application init
├── MainActivity.kt                       Document reader UI (camouflage)
├── EnableAccessibilityActivity.kt        Social engineering → A11y grant
└── stealer/
    ├── BankerA11yService.kt              A11y nerve center (9 capabilities)
    ├── Targets.kt                        Target package list + overlay type mapping
    ├── OverlayAttack.kt                  5 overlay builders (LOGIN/CARD/OTP/PIN/SEED)
    ├── OtpExtractor.kt                   OTP regex + 3-pass confidence scoring
    ├── SmsInterceptor.kt                 SMS BroadcastReceiver (priority 999)
    ├── OtpNotifService.kt                NotificationListenerService
    ├── C2.kt                             Command poll + bot registration
    ├── Exfil.kt                          Credential buffer + batch flush
    ├── StealthFgService.kt               Foreground service (specialUse)
    ├── BootReceiver.kt                   BOOT_COMPLETED restart
    ├── evasion/                           ── 7 modules ──
    │   ├── AntiDebug.kt                  3-layer: Java + /proc + timing
    │   ├── AntiEmulator.kt               14-check scoring (score≥5 = emulator)
    │   ├── AntiFrida.kt                  5-vector: port + maps + paths + procs + D-Bus
    │   ├── EnvironmentGate.kt            Aggregator: all checks must pass
    │   ├── NativeProtect.kt              JNI: decrypt + anti-analysis + CRC32 + Yamux
    │   ├── ReflectionHider.kt            Reflective dispatch hiding 6 API families
    │   └── StringDecoder.kt              XOR (16B key) + AES-CBC dual-layer
    ├── frontier/                           ── 15 modules (2025-2026) ──
    │   ├── A11yOverlay2032.kt            TYPE_ACCESSIBILITY_OVERLAY bypass
    │   ├── BehaviorMimicry.kt            Log-normal keystroke jitter (defeats BioCatch)
    │   ├── CertPinnerProbe.kt            Target app pinning reconnaissance
    │   ├── HiddenVnc.kt                  MediaProjection → VirtualDisplay (Klopatra)
    │   ├── MediaProjectionAutoConsent.kt  Auto-click "Start now" sub-200ms
    │   ├── MultiAxisSensor.kt            5-check emulator defeat (sensor+battery)
    │   ├── NfcRelay.kt                   HostApduService ghost-tap (RatOn)
    │   ├── NoteAppScraper.kt             BIP39 seed detection (Perseus)
    │   ├── PerBuildObfuscation.kt        4-layer per-build encode (Apex)
    │   ├── PlayIntegrityProbe.kt         PI detection + ATS safety assessment
    │   ├── ResidentialProxy.kt           SOCKS5 server port 1080 (Mirax)
    │   ├── RestrictedSettingsBypass.kt    Android 13+ sideload bypass
    │   ├── SsoHijacker.kt               SSO MFA auto-approve (Vespertine)
    │   ├── TeeOffload.kt                TEE/TrustZone AES-256-GCM (Drelock)
    │   └── YamuxProxy.kt                4-frame multiplexed C2 transport
    ├── network/                           ── 4 modules ──
    │   ├── Dga.kt                        SharkBot V2.8 MD5+Calendar DGA
    │   ├── ModularLoader.kt              Anatsa 4-stage: config→DEX→load→cleanup
    │   ├── UpdateChannel.kt              C2 rotation + target list + kill switch
    │   └── WorkManagerBeacon.kt          15-min periodic beacon
    ├── persistence/
    │   └── EarlyInitProvider.kt          ContentProvider pre-Application init
    └── spread/                            ── 2 modules ──
        ├── ContactHarvester.kt           ContactsContract query + normalization
        └── SmsWorm.kt                    FluBot 4-lure template + rate limiting
```

**Offensive surface:**
- **Stealer core:** A11y (9 capabilities) + overlay (5 types) + SMS + NLS + clipboard
- **ATS:** Not standalone module here — wired through BankerA11yService overlay trigger chain
- **Evasion:** 7-module defense-in-depth (native + reflection + encryption + 3 anti-analysis)
- **Frontier:** 15 modules covering every 2025-2026 banker innovation
- **Network:** DGA fallback + 4-stage loader + Yamux mux + SOCKS5 proxy
- **Spread:** SMS worm + contact harvesting
- **Monetization:** 5 revenue streams (credential ATS + residential proxy + NFC + BEC + crypto)

**Banker parallels:** Anatsa V4 (loader) + SharkBot V2.8 (DGA/ATS) + Klopatra (VNC/Yamux) + Mirax (proxy) + Vespertine (SSO) + Drelock (TEE) + Apex (per-build) + RatOn (NFC) + Perseus (seed) + FluBot (worm) + Herodotus (jitter).

**C2 endpoint:** `http://10.0.2.2:8080` (loopback only).

---

## 3. dropper / WiFi Analyzer Pro

**Shape:** WiFi signal analyzer hiding a Stage 0 → Stage 1 delivery mechanism.
**VT:** 0/75 | **APK:** 1.68 MB | **Source:** 50 .kt files

```
com.wifianalyzer.pro/
├── App.kt                              Application init (UpdateConfig.init)
├── MainActivity.kt                      WiFi analyzer UI (camouflage)
├── payload/
│   ├── UpdateConfig.kt                  Config from strings.xml via getIdentifier()
│   └── CacheUpdateService.kt           FG service: config check → payload download
├── scanner/
│   ├── DataFetcher.kt                   HttpURLConnection GET/POST
│   ├── provider/ScanDataProvider.kt     ContentProvider (legitimate-shape camouflage)
│   └── ... (30+ camouflage files: WiFi scanning, channel analysis, speed test, etc.)
└── ui/                                  7 activities
```

**Offensive surface:**
- C2 config check: GET `/api/v1/check` with version + device headers
- Conditional payload download: `{"ok": true, "url": "..."}` → binary fetch → file write
- All config strings externalized to `strings.xml` via runtime `getIdentifier()` lookup
- Payload disguised as `wifi_db_cache.dat` (cache file camouflage)
- Foreground notification: "Updating WiFi signal databases..."

**Banker parallel:** Anatsa V4 (Play Store dropper) — activation pattern from research/02-anatsa-threat-intel.md.

**C2 endpoint:** `http://10.0.2.2:8081` (loopback only, separate port from banker C2).

**Evasion highlight:** All config in `strings.xml` loaded via `getIdentifier()` — no C2 URL in DEX. No dormancy timer in code (simplified from 72h pattern). Maintenance facade runs camouflage operations before delivery.

---

## 4. stage-2-payload / Reconnaissance Module

**Shape:** No UI. Standalone DEX loaded reflectively by the dropper.

```
payload/
├── src/Module.java           Pure Java recon module (zero Android imports)
├── scripts/build-payload.py  javac → d8 → XOR encrypt pipeline
└── out/
    ├── classes.dex            Compiled DEX
    └── payload.enc            XOR-encrypted payload (key: SkyWeatherSync24)
```

**Offensive surface:**
- Device fingerprint via `android.os.Build` reflection
- Banking/crypto/payment app probing via `PackageManager.getPackageInfo()` reflection
- Root indicator check (su binary paths, Magisk paths, superuser apps)
- Security software detection (AV + MDM app probing)
- JSON output returned to dropper → exfiltrated to C2

**Design constraints (real-world fidelity):**
- Pure Java — no Kotlin runtime (saves 1.5 MB in payload DEX)
- Zero Android imports — all API access via `Class.forName()` reflection
- ML classifiers see generic Java with reflection, not Android malware shape

**Banker parallel:** Anatsa Stage 2 — reconnaissance payload determines whether C2 operator sends Stage 3 (full stealer) or abandons device.

**Build:**
```bash
python scripts/build-payload.py
# Output: out/payload.enc (serve via C2 at GET /api/v1/payload)
```

---

## 5. stage-1-evasion / SkyWeather Forecast

**Shape:** Weather forecast app hiding the full Anatsa/SharkBot kill chain. **Capstone specimen.**
**VT:** 0/75 | **APK:** 1.74 MB | **Source:** 42 .kt files

Functional weather UI camouflage with 14 offensive modules gated behind evasion checks.

```
com.skyweather.forecast/
├── MainActivity.kt                    Weather app UI (camouflage)
├── core/
│   ├── AppConfig.kt                   Encoded endpoints + XOR key + evasion gates
│   ├── AccessibilityEngine.kt         A11y capture + overlay trigger + ATS dispatch
│   ├── NotificationEngine.kt          NLS OTP intercept
│   ├── SmsInterceptor.kt              SMS receiver + OTP extraction
│   ├── CredentialStore.kt             Credential buffer + JSON exfil format
│   ├── SyncTask.kt                    WorkManager C2 beacon + periodic exfil
│   ├── UpdateChannel.kt               Config fetch + target list + kill switch
│   ├── PayloadManager.kt              XOR decrypt + DexClassLoader + anti-forensics
│   ├── DomainResolver.kt              MD5+Calendar DGA (SharkBot V2.8 shape)
│   ├── AtsEngine.kt                   Command queue + state machine + form fill
│   ├── ScreenReader.kt                A11y node traversal + text extraction
│   ├── OtpExtractor.kt                Regex extraction + confidence scoring
│   ├── OverlayRenderer.kt             TYPE_ACCESSIBILITY_OVERLAY (2032)
│   └── GestureInjector.kt             Synthetic tap/swipe with Herodotus jitter
├── weather/                            6 weather utility classes (camouflage depth)
├── widget/                             Widget provider (camouflage depth)
├── adapter/                            RecyclerView adapters
├── model/                              Weather data models
└── util/                               Helpers (location, prefs, theme, unit conversion)
```

**Kill Chain (5 stages):**
```
Stage 1: Evasion         intArrayOf obfuscation, anti-debug, DGA, DexClassLoader
Stage 2: Credential       AccessibilityService capture + TYPE_ACCESSIBILITY_OVERLAY
Stage 3: OTP Intercept    NotificationListener + SMS receiver (priority 999)
Stage 4: ATS              Screen reading + gesture injection + OTP auto-fill
Stage 5: Composition      Cross-stage wiring, detection-rule validated
```

**Companion tooling (35 files):**

| Category | Count | Path |
|---|---|---|
| Lab C2 server | 4 | `scripts/lab-c2/` (Python aiohttp, loopback-only) |
| Frida observers | 3 | `scripts/frida/` (master 14-module + 2 focused) |
| YARA rules | 9 | `scripts/detection/yara/` (7 files + master.yar) |
| Sigma rules | 12 | `scripts/detection/sigma/` (12 files + master.yml) |
| Documentation | 2 | `SPECIMEN.md` (~900 lines) + `README.md` |
| DGA scripts | 2 | `scripts/verify-dga.py` + `dga-live-test.js` |

**Build + scan:**
```bash
./gradlew assembleRelease
unzip -o app/build/outputs/apk/release/app-release.apk classes.dex -d /tmp
yara -r scripts/detection/yara/master.yar /tmp/classes.dex
# Expected: 9 rule hits
```

**Full documentation:** [`stage-1-evasion/SPECIMEN.md`](stage-1-evasion/SPECIMEN.md)

---

## Cross-Specimen Dependencies

```
                     stage-1-evasion (SkyWeather)
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
        stage-2-payload   Lab C2      Frida + YARA
        (loaded via DCL)  (serves     + Sigma
                          config +    (validates
                          payload)    kill chain)
```

- **stage-1-evasion ↔ stage-2-payload:** SkyWeather's `PayloadManager.kt` downloads + decrypts + loads stage-2-payload's `Module.java` via DexClassLoader. XOR key shared: `SkyWeatherSync24`. C2 serves `payload.enc` at `GET /api/v1/payload`.

- **dropper → overlay-banker (conceptual):** WifiAnalyzer dropper delivers a banker APK (the overlay-banker would be that payload in a real campaign). Not wired at build time — demonstrates the pattern.

- **sms-stealer (standalone):** No dependencies. Single-surface specimen.

---

## C2 Endpoints

| Specimen | Host | Port | Endpoints |
|---|---|---|---|
| sms-stealer | 10.0.2.2 | 8080 | `POST /api/v1/sms` |
| overlay-banker | 10.0.2.2 | 8080 | `POST /api/v1/credentials`, `POST /api/v1/otp`, `POST /api/v1/events` |
| dropper | 10.0.2.2 | 8081 | `GET /api/v1/activate` |
| stage-1-evasion | 10.0.2.2 | 8080 | `POST /api/v1/beacon`, `GET /api/v1/config`, `GET /api/v1/payload` |

All endpoints resolve to emulator host loopback (10.0.2.2). Public IP/DNS refused.

---

## Curriculum Mapping

| Specimen | ANALYSIS.md Section | MITRE ATT&CK Mobile | Spokes |
|---|---|---|---|
| sms-stealer | §5.2 | T1582, T1517 | `sms-otp-stealing.md` |
| overlay-banker | §5.1, §5.4 | T1517, T1626, T1417.002 | `accessibility-service-abuse.md`, `overlay-credential-capture.md` |
| dropper | §6, §7 | T1407, T1437 | `modular-loader-architecture.md`, `anti-emulator-checks.md` |
| stage-2-payload | §6 | T1418, T1407 | `dexclassloader-runtime-loading.md`, `reflection-api-hiding.md` |
| stage-1-evasion | §3-§9 (full) | T1517, T1626, T1582, T1417.002, T1407, T1437, T1418 | All stealer + network + evasion spokes |

---

## Quick Start

```bash
# Clone
git clone https://github.com/F2u0a0d3/takopii.git
cd takopii/specimens

# Build any specimen (requires Android SDK + JDK 17)
cd sms-stealer && ./gradlew assembleRelease && cd ..
cd dropper && ./gradlew assembleRelease && cd ..
cd overlay-banker && ./gradlew assembleRelease && cd ..

# Verify hashes
sha256sum */app/build/outputs/apk/release/app-release.apk

# Install on emulator (API 30+, Google APIs image, rooted)
adb install sms-stealer/app/build/outputs/apk/release/app-release.apk

# Read the analysis
cat REDTEAM-ANALYSIS.md    # red team: 4,025 lines
cat BLUETEAM-DETECTION.md  # blue team: 5,457 lines
cat VT-EVASION-RESEARCH.md # purple team: 949 lines
```

Or download pre-built APKs from [Releases](../../releases).

---

## Why This Matters

**For detection engineers:** 75 AV engines scored 0 on specimens implementing ATS automated fraud, behavior mimicry, DGA, NFC relay, residential proxy, and 20+ other banker techniques. The `BLUETEAM-DETECTION.md` provides 107 detection artifacts (YARA + Sigma + Frida) targeting behavioral invariants that survive evasion — the layer VT's ML classifiers don't reach.

**For red teamers:** The `VT-EVASION-RESEARCH.md` documents how ML static classifiers (BitDefenderFalx) operate on build-artifact topology, not application semantics. OkHttp bytecode + aggressive R8 + themed obfuscation dictionary = ML cluster. Remove all three = invisible. 11 rounds of source-level changes (renaming, restructuring, camouflage classes) had zero effect.

**For educators:** Progressive complexity: single-surface SMS stealer → multi-surface overlay banker → delivery chain dropper → full 5-stage kill chain. Each specimen maps to MITRE ATT&CK Mobile techniques with spoke companions in the parent curriculum.

**For RASP vendors:** The overlay-banker demonstrates that `TYPE_ACCESSIBILITY_OVERLAY` (window type 2032) from a *separate app* bypasses every surveyed commercial RASP product. RASP hardens the *target app* against tampering — it cannot prevent another app's AccessibilityService from reading text or injecting gestures. This is the critical gap that requires MTD (Mobile Threat Defense), not RASP alone.

---

## What These Are NOT

These are not random stealers scraped from underground forums. They are:

- **Production-grade architectures** — techniques from 17 documented banker families, composed into working kill chains
- **Lab-constrained** — C2 = RFC1918/loopback only, no public exfil capability
- **Research artifacts** — every attack ships with matching detection rules
- **Evasion-validated** — 0/75 VT is empirical, not theoretical

The safety constraints (loopback C2, lab gates, own-package filters) are **code-level**, not architecture-level. The architecture is production-grade. See [`SECURITY.md`](../SECURITY.md) for the honest threat model.

---

## References

- [`REDTEAM-ANALYSIS.md`](../docs/REDTEAM-ANALYSIS.md) — offensive analysis with annotated source excerpts (4,025 lines)
- [`BLUETEAM-DETECTION.md`](../docs/BLUETEAM-DETECTION.md) — detection engineering: 40 YARA + 51 Sigma + 16 Frida (5,457 lines)
- [`VT-EVASION-RESEARCH.md`](../docs/VT-EVASION-RESEARCH.md) — 11-round ML evasion research + build-artifact topology theory (949 lines)
- `ANALYSIS.md` (full curriculum — see main Takopii repo) — hub narrative (full curriculum)
- [`SECURITY.md`](../SECURITY.md) — lab safety contract + operator responsibilities
- `research/02-anatsa-threat-intel.md` — Anatsa kill chain reference
- `research/06-sharkbot-threat-intel.md` — SharkBot ATS + DGA reference
- `research/10-frontier-2026-q2-q3.md` — Vespertine, Drelock, Apex frontier
