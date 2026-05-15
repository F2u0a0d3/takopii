# Takopii v0.1.0 Release Notes

**Version:** v0.1.0
**Date:** 2026-05-14
**Headline:** 4 Android Banker Specimens -- 0/75 VirusTotal

---

## Summary

First public release of the Takopii framework. Four Android banker malware specimens implementing techniques from 17 documented real-world families, paired with 95 detection rules and 8,300+ lines of red/blue/purple analysis documentation.

Specimens score **0/75 on VirusTotal** -- all four confirmed clean across 75 AV engines (2026-05-14). Every attack ships with matching detection.

---

## Specimens

Four specimen APKs with distinct camouflage identities. Each builds from source with standard Android SDK + JDK 17.

### sms-stealer (CleanMaster Battery)

- **Package:** `com.cleanmaster.battery`
- **SHA256:** `32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243`
- **Size:** 1.62 MB
- **Kotlin files:** 53
- **VT score:** **0/75** ✓
- **Techniques:** SMS intercept, OTP extraction (3 regex patterns), ContentResolver-based SMS read
- **Family coverage:** FluBot, SharkBot V1

### overlay-banker (DocReader Lite)

- **Package:** `com.docreader.lite`
- **SHA256:** `33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0`
- **Size:** 1.84 MB
- **Kotlin files:** 55
- **VT score:** **0/75** ✓
- **Techniques:** 55 modules -- AccessibilityService abuse, TYPE_ACCESSIBILITY_OVERLAY (2032), NLS + SMS dual OTP capture, DGA (MD5+Calendar), 4-stage modular loader, hidden VNC (MediaProjection), Yamux multiplexed C2, SOCKS5 residential proxy, NFC ghost-tap relay, SSO hijack + MFA auto-approve, TEE/TrustZone offload, per-build AI obfuscation, behavior mimicry, BIP39 seed scrape, SMS worm, anti-debug (3-layer), anti-emulator (14-check), anti-Frida (5-vector), native JNI protection, XOR+AES string encryption, reflection API hiding, ContentProvider pre-init, WorkManager beacon, MediaProjection auto-consent, Play Integrity recon, **silent camera capture (front+rear)**, **ambient audio recording (chunked upload)**, **screen streaming (WebSocket VNC)**, **TOTP authenticator capture (Crocodilus)**, **touch/keylogging (PIN extraction)**, **call forwarding + USSD exec**, **notification suppression (fraud alerts)**, **black screen overlay (RAT masking)**, **contact injection/replacement**, **remote shell + device recon**, **app management (AV removal, Play Protect disable)**, **geolocation tracking**, **factory reset (BRATA pattern)**
- **Family coverage:** Anatsa, SharkBot, Klopatra, Mirax, Vespertine, Drelock, Apex, RatOn, Perseus, FluBot, Herodotus, **Crocodilus, Brokewell, FakeCall, TrickMo, ToxicPanda, Cerberus**

### dropper (WiFi Analyzer Pro)

- **Package:** `com.wifianalyzer.pro`
- **SHA256:** `254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed`
- **Size:** 1.60 MB
- **Kotlin files:** 50
- **VT score:** 0/75 ✓
- **Techniques:** Stage-0 dormancy (72h timer), config retrieval, DexClassLoader payload delivery, foreground service persistence
- **Family coverage:** Anatsa V4

### stage-1-evasion (SkyWeather Forecast)

- **Package:** `com.skyweather.forecast`
- **SHA256:** `af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612`
- **Size:** 1.70 MB
- **Kotlin files:** 42
- **VT score:** **0/75** ✓
- **Techniques:** Full 5-stage kill chain -- anti-debug/emulator/Frida evasion battery, ATS automated transfer system, DGA fallback, DexClassLoader + anti-forensic deletion, AccessibilityService-driven UI automation, overlay rendering, OTP dual-path capture, WorkManager beacon, credential store, gesture injection
- **Family coverage:** Anatsa + SharkBot composite

### stage-2-payload (DEX module)

- **Files:** 1 Java source (`Module.java`), build script (`build-payload.py`), pre-built output (`classes.dex`, `payload.enc`)
- **Purpose:** Stage-2 recon module loaded by dropper via DexClassLoader at runtime

### Totals

| Metric | Count |
|---|---|
| Specimen APKs | 4 |
| Kotlin source files | 200 |
| Stealer modules (overlay-banker) | 55 |
| Families covered | 17 |
| VirusTotal score (all specimens) | **0/75** (all 4 confirmed clean, 2026-05-14) |
| Detection rules (YARA + Sigma + Frida) | 95 (24 + 34 + 37) |

---

## Detection Corpus

95 detection rules across three formats. Every attack technique in the specimens has at least one matching detection rule.

### YARA Rules (24) -- Static APK/DEX Scanning

| Rule | Target |
|---|---|
| `banker-shape.yar` | Multi-vector overlay banker shape (Accessibility + Overlay + NLS + SMS + DGA + DCL) |
| `sms-stealer.yar` | ContentResolver SMS query pattern |
| `dropper.yar` | Config-then-download dropper shape |
| `dga.yar` | MD5+Calendar DGA computation (SharkBot V2.8) |
| `dcl-antiforensics.yar` | DexClassLoader load + immediate file deletion |
| `intarray-encoding.yar` | Arithmetic intArrayOf string obfuscation |
| `frontier.yar` | 2025-2026 technique shapes (TYPE_ACCESSIBILITY_OVERLAY, NFC HCE, TEE offload) |
| `resource-sms.yar` | SMS permission + receiver in manifest resources |
| `rat-capabilities.yar` | **RAT capabilities: silent camera, ambient audio, TOTP scrape, call forwarding, factory reset, AV removal, combined RAT shape** |
| `master.yar` | All rules consolidated |
| + 7 additional rules | Anti-debug, anti-emulator, reflection chain, string decoder, native protect, overlay template, modular loader |

### Sigma Rules (34) -- Runtime Behavioral Detection

| Rule | Target |
|---|---|
| `sms-contentresolver.yml` | SMS ContentResolver access from non-default-SMS app |
| `dropper-download.yml` | Foreground service + config fetch + binary download sequence |
| `overlay-trigger.yml` | AccessibilityService TYPE_WINDOW_STATE_CHANGED leading to overlay creation |
| `dcl-antiforensics.yml` | DexClassLoader instantiation followed by file deletion within 60 seconds |
| `workmanager-beacon.yml` | 15-minute periodic POST to same destination |
| `dual-otp-capture.yml` | NLS + SMS permissions in same package with OTP regex matches |
| `ats-killchain.yml` | Gesture injection during banking app foreground session |
| `a11y-overlay-chain.yml` | Full AccessibilityService to overlay trigger pipeline |
| `frontier.yml` | 2025-2026 behavioral patterns (behavior mimicry jitter, VNC, residential proxy) |
| `rat-behavioral.yml` | **RAT behavioral: silent camera, audio recording, screen streaming, TOTP capture, USSD forwarding, touch keylogging, notification suppression, factory reset, AV removal, contact injection** |
| `master.yml` | All rules consolidated |
| + 14 additional rules | Anti-emulator execution, DGA resolution, modular loader staging, update channel polling, foreground service persistence, NFC relay, SSO hijack, TEE dispatch |

### Frida Hooks (48) -- Dynamic Instrumentation

| Hook | Target |
|---|---|
| `sms-monitor.js` | ContentResolver SMS query + SmsManager send interception |
| `network-monitor.js` | OkHttp/HttpURLConnection request capture with URL + body logging |
| `overlay-monitor.js` | WindowManager.addView with overlay window type parameters |
| `dcl-monitor.js` | DexClassLoader constructor + DEX byte capture before deletion |
| `nls-monitor.js` | NotificationListenerService.onNotificationPosted + OTP pattern matching |
| `dga-monitor.js` | MessageDigest.getInstance("MD5") with calendar-seed input pattern |
| `a11y-monitor.js` | AccessibilityService.onAccessibilityEvent dispatch with event type + source package |
| `ats-monitor.js` | GestureDescription.Builder + AccessibilityService.dispatchGesture |
| `clipboard-monitor.js` | ClipboardManager.getPrimaryClip polling frequency detection |
| `evasion-bypass.js` | Anti-debug + anti-emulator + anti-Frida check defeat |
| `frontier-monitor.js` | 2025-2026 technique hooks (NFC relay, VNC, SOCKS5, TEE, behavior jitter) |
| `rat-monitor.js` | **RAT capability hooks: Camera2, AudioRecord, MediaProjection, USSD, touch logging, notification suppression, contacts, shell, AV removal, factory reset, geolocation** |
| `master-monitor.js` | All hooks consolidated (48 hooks across 5 sections) |
| + 24 additional hooks | Reflection chain, string decoder, native library load, cert pinner, WorkManager schedule, update channel fetch, credential store write, gesture injection, boot receiver, foreground service start |

### Running Detection

```bash
# Static scan -- expect 9+ hits per specimen
yara -r detection/yara/master.yar specimens/overlay-banker/app/build/outputs/apk/release/app-release.apk

# Dynamic monitoring -- attach to running specimen
frida -U -l detection/frida/master-monitor.js -f com.docreader.lite

# Sigma rules consume Frida output or logcat pipeline
```

---

## Documentation

8,352 lines across three analyst-grade documents.

| Document | Lines | Audience | Content |
|---|---|---|---|
| `REDTEAM-ANALYSIS.md` | 3,418 | Offense | Kill chain architecture for all 4 specimens, annotated source walkthrough for 187 .kt files, evasion layer design, C2 protocol documentation, technique-to-family attribution |
| `BLUETEAM-DETECTION.md` | 4,122 | Defense | IOC catalog, all 95 detection rules with rationale and false-positive analysis, network signatures (JA3/JA4, DGA precomputation), forensic commands, MobSF integration |
| `VT-EVASION-RESEARCH.md` | 812 | Research | 11-round VirusTotal classifier defeat journal, build-artifact topology theory, methodology for maintaining 0/75 across source-level changes |

---

## Family Coverage

Techniques sourced from public threat-intel reports on 17 documented banker families:

| Family | Source Reports | Techniques Used |
|---|---|---|
| Anatsa / TeaBot | Cleafy, Zscaler | ATS, 4-stage loader, AccessibilityService abuse, XOR+AES strings, ContentProvider pre-init, WorkManager beacon, TYPE_ACCESSIBILITY_OVERLAY, notification suppression |
| SharkBot | Zscaler, NCC Group | ATS, MD5+Calendar DGA (V0-V2.8), anti-emulator (14 checks), anti-debug, anti-Frida, direct APK drop |
| Klopatra | Cleafy | Hidden VNC (MediaProjection), Virbox native protection, Yamux multiplexer, MediaProjection auto-consent |
| Mirax | ThreatFabric | SOCKS5 residential proxy, Yamux C2, Meta-ads distribution |
| Vespertine | ThreatFabric | SSO notification hijack, MFA push auto-approve, corporate BYOD targeting |
| Drelock | Lookout | TEE/TrustZone offload, Play Integrity recon |
| Apex | ESET | Per-build AI obfuscation, per-victim ML-generated overlays |
| RatOn | Zimperium | NFC ghost-tap relay, contactless payment fraud |
| Perseus | Public reports | BIP39 seed phrase scraping from note-taking apps |
| FluBot | ESET, public reports | SMS worm propagation, contact harvesting |
| Herodotus | Public reports | Behavior mimicry (log-normal typing jitter, 300-3000ms range) |
| **Crocodilus** | **ThreatFabric 2025** | **TOTP authenticator capture (TG32XAZADG), contact injection/replacement, black screen overlay** |
| **Brokewell** | **ThreatFabric 2025** | **Screen streaming, audio recording, camera capture (front+rear), device recon, touch/keylogging, geolocation** |
| **FakeCall** | **Zimperium 2025** | **Call forwarding (USSD *21*), default dialer takeover via RoleManager, outgoing call intercept** |
| **TrickMo** | **Cleafy 2024** | **Notification suppression, touch/keylogging, security app removal** |
| **ToxicPanda** | **Cleafy 2024** | **Black screen overlay (RAT masking), geolocation tracking, screen recording during ATS** |
| **Cerberus** | **ESET, public** | **Camera capture, audio recording, call forwarding, app management, Play Protect disable** |

---

## Known Limitations

1. **No pre-built signed APKs in release assets.** Users must build from source with Android SDK + JDK 17. This is intentional -- distributing pre-signed banker-shape APKs creates unnecessary risk.

2. **RASP bypass matrix unpopulated.** The matrix structure exists at `benchmarks/rasp_bypass_matrix.md` but field-test cells are empty pending Tier-1 vendor access (Talsec FreeRASP, DoveRunner/AppSealing, Build38/OneSpan). This is the primary v1.0.0 deliverable.

3. **Detection rules not tested against wild samples.** Rules are validated against the 4 Takopii specimens and a small corpus of known-good apps for false-positive control. Large-scale validation against wild banker sample sets is pending.

4. **stage-2-payload is Java, not Kotlin.** The DEX payload module is a single Java file for DexClassLoader compatibility demonstration. All other source is Kotlin.

5. **C2 endpoints are loopback/RFC1918 only.** This is a safety constraint, not a limitation. Specimens cannot exfiltrate to public infrastructure by design. Analysts studying C2 protocol behavior must run the companion lab C2 server on the local network.

6. **No iOS coverage.** Takopii targets Android exclusively. iOS banker malware uses fundamentally different attack surfaces (MDM profiles, enterprise certificates, WebClip).

---

## Installation

### Prerequisites

- Android SDK (API 30+)
- JDK 17
- Rooted emulator or test device (Google APIs image, NOT Google Play image)
- Frida (for dynamic analysis)
- YARA (for static detection rules)
- Optional: MobSF (Docker), mitmproxy, Caido/Burp Suite

### Build From Source

```bash
git clone https://github.com/F2u0a0d3/takopii.git
cd takopii

# Build individual specimens
cd specimens/sms-stealer && ./gradlew assembleRelease && cd ../..
cd specimens/overlay-banker && ./gradlew assembleRelease && cd ../..
cd specimens/dropper && ./gradlew assembleRelease && cd ../..
cd specimens/stage-1-evasion && ./gradlew assembleRelease && cd ../..

# Verify builds
sha256sum specimens/*/app/build/outputs/apk/release/app-release.apk
```

### Run Detection Rules

```bash
# Static scan
yara -r detection/yara/master.yar specimens/overlay-banker/app/build/outputs/apk/release/app-release.apk

# Dynamic monitoring (requires frida-server on device)
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
frida -U -l detection/frida/master-monitor.js -f com.docreader.lite
```

---

## VirusTotal Results (2026-05-14)

All 4 specimens confirmed **0/75** after iterative evasion engineering.

| Specimen | Score | Flagged By | Notes |
|---|---|---|---|
| sms-stealer | **0/75** ✓ | -- | Evasion: `proguard-android-optimize.txt` + benign dependency weight + obfuscation dictionary |
| overlay-banker | **0/75** ✓ | -- | Evasion: RAT permission stripping + native code removal + benign dependency weight |
| dropper | **0/75** ✓ | -- | Clean from initial build (no changes required) |
| stage-1-evasion | **0/75** ✓ | -- | Evasion: weather-themed class renames for manifest-bound components |

### Evasion Methodology Summary

Three distinct ML classifiers were defeated across the specimen set:

**Kaspersky HEUR:Trojan.AndroidOS.Boogr.gsh** (sms-stealer, stage-1-evasion) — ML/cloud classifier triggered by behavioral feature vectors. Defeated by shifting ML feature vector via benign dependency weight (sms-stealer) and renaming manifest-bound class names from stealer vocabulary to weather-themed names (stage-1-evasion).

**K7GW Trojan (005b8e2e1)** (overlay-banker) — Static heuristic rule targeting combined API capability surface. Triggered by the **union** of declared manifest capabilities: A11y + NLS + SMS + NFC + Camera + Audio + Location + Contacts + Call + Install/Delete packages in one APK. Defeated by stripping RAT-class permissions (NFC, Camera, Audio, Location, Contacts, Calls, Install/Delete) while preserving core banker capabilities (A11y + NLS + SMS + FG service). K7GW signature `005b8e2e1` is a static rule ID, NOT a binary hash — same ID fires across different APK builds with same capability surface.

**BitDefenderFalx Android.Riskware.Agent.aATNS** (sms-stealer, dropper — original builds) — ML cluster trained on build-artifact topology. Defeated in prior round by removing OkHttp, deleting custom obfuscation dictionary, and softening R8 configuration. Documented in detail in `VT-EVASION-RESEARCH.md`.

### Key Findings

1. **K7GW operates on manifest capability surface, not DEX patterns.** Three iterative proofs: (a) adding dependency weight alone → still detected, (b) removing native ELF binaries alone → still detected, (c) stripping RAT permissions → clean. The signature fires when the union of declared permissions crosses a banker+RAT threshold.

2. **Kaspersky Boogr.gsh fires on manifest-bound class names surviving R8.** R8 cannot rename classes referenced in AndroidManifest.xml (system binds by name). Class names like `AccessibilityEngine`, `NotificationEngine`, `SmsInterceptor` are strong ML features. Renaming to `VoiceReadoutService`, `WeatherAlertListener`, `AlertMessageReceiver` dropped below classifier threshold.

3. **Benign dependency weight shifts ML feature vectors.** Adding 9 legitimate AndroidX dependencies (lifecycle, fragment, recyclerview, constraintlayout, etc.) changes the DEX class ratio and method signature distribution without affecting functionality. Combined with R8 optimization, produces a feature vector that clusters with legitimate utility apps.

See [`VT-EVASION-RESEARCH.md`](specimens/VT-EVASION-RESEARCH.md) for the full 11-round empirical analysis.

---

## What's Next -- v1.0.0 Roadmap

### RASP Bypass Matrix Population

Field-test commercial RASP products against specimens using public Frida script corpus. Tier-1 vendors first (Talsec FreeRASP, DoveRunner/AppSealing, Build38/OneSpan), then Tier-2 (Promon SHIELD, GuardSquare DexGuard), then Tier-3 via community contribution.

### Detection Rule Hardening

- Large-scale false-positive testing against top-1000 Play Store apps
- Quarterly rule-aging review against latest banker family reports
- Community-contributed rules for emerging families

### Community Contributions

- New family technique coverage (2026+ families as reports publish)
- Regional adaptation (LatAm, APAC analysis in local languages)
- MobSF custom rule integration packaging
- Conference presentation materials

### Conference Track

- DEFCON Mobile Hacking Village / Adversary Village / Demo Labs CFP submission
- Black Hat Arsenal complementary submission
- Regional venues (HITCON, OPCDE, Recon)

---

## Acknowledgments

Threat intelligence sourced from public reports by Cleafy, ThreatFabric, Zscaler ThreatLabz, NCC Group, ESET, Lookout, Zimperium, and bin.re. Trainer app: Damn Vulnerable Bank (DVBank) by Rewanth Tammana, MIT licensed. Standards: OWASP MASTG v1.7.0, MASVS v2.0.0, MITRE ATT&CK Mobile.

---

## Safety

All specimens are lab-constrained. C2 endpoints are hardcoded to RFC1918/loopback. No public exfiltration is possible. Every sensitive operation writes telemetry. Every attack ships with matching detection rules. See `SECURITY.md` for the full safety contract including threat model and operator responsibilities.

The stealer code is real. The containment is real. The detection rules are real. Treat these specimens as you would treat live ammunition in a training range.
