# Takopii

### 4 Android Banker Specimens. 0/66 VirusTotal. Full Kotlin Source.

> Production-grade banker malware architecture — techniques from 17 real-world families — with matching detection rules. Zero family attribution from any AV engine.

[![VT Score](https://img.shields.io/badge/VirusTotal-0%2F66-brightgreen?style=for-the-badge&logo=virustotal)](specimens/)
[![Specimens](https://img.shields.io/badge/Specimens-4%20APKs-blue?style=for-the-badge)](specimens/)
[![Kotlin](https://img.shields.io/badge/Kotlin-200%20files-7F52FF?style=for-the-badge&logo=kotlin)](specimens/)
[![Families](https://img.shields.io/badge/Families-17%20real--world-red?style=for-the-badge)](specimens/)
[![YARA](https://img.shields.io/badge/YARA-24%20rules-orange?style=for-the-badge)](detection/yara/)
[![Sigma](https://img.shields.io/badge/Sigma-34%20rules-yellow?style=for-the-badge)](detection/sigma/)
[![Frida](https://img.shields.io/badge/Frida-13%20monitors-purple?style=for-the-badge)](detection/frida/)
[![License](https://img.shields.io/badge/License-Research-lightgrey?style=for-the-badge)](SECURITY.md)

---

## What's Inside

| # | Specimen | Camouflage | Techniques | VT | Families |
|:-:|---|---|---|:-:|---|
| 1 | **sms-stealer** | CleanMaster Battery | SMS intercept, OTP extraction | **0/66** | FluBot, SharkBot V1 |
| 2 | **overlay-banker** | Doc Reader Lite | 55 modules, 17 family techniques | **0/66** | Anatsa, SharkBot, Klopatra, Mirax, Vespertine, Drelock, Apex, RatOn, Perseus, FluBot, Herodotus, Crocodilus, Brokewell, FakeCall, TrickMo, ToxicPanda, Cerberus |
| 3 | **dropper** | WiFi Analyzer Pro | Stage-0 dormancy + delivery | **0/66** | Anatsa V4 |
| 4 | **stage-1-evasion** | SkyWeather Forecast | Full 5-stage kill chain + ATS | **0/66** | Anatsa + SharkBot composite |

> Most wild banker samples implement 3-5 techniques. The **overlay-banker** composes **40+ techniques from 17 families** in a single APK.

<details>
<summary><strong>VirusTotal Proof — 0/66 All Specimens (click to expand)</strong></summary>

<br>

| Specimen | Camouflage | SHA256 | VT | Verify |
|---|---|---|:-:|:-:|
| **sms-stealer** | Battery Boost Pro | `32f37e...6e243` | **0/66** | [View on VT](https://www.virustotal.com/gui/file/32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243) |
| **overlay-banker** | Doc Reader Lite | `332079...e2b0` | **0/66** | [View on VT](https://www.virustotal.com/gui/file/33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0) |
| **dropper** | WiFi Analyzer Pro | `254465...9ee7ed` | **0/66** | [View on VT](https://www.virustotal.com/gui/file/254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed) |
| **stage-1-evasion** | SkyWeather Forecast | `af5ceb...01612` | **0/66** | [View on VT](https://www.virustotal.com/gui/file/af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612) |

**Full SHA256 hashes:**
```
sms-stealer:      32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243
overlay-banker:   33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0
dropper:          254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed
stage-1-evasion:  af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612
```

> Scanned 2026-05-14. Overlay-banker flagged by Zenbox sandbox as "MALWARE ADWARE TROJAN EVADER" + Suricata LOW severity 1 — static AV engines still score 0/66. Click "View on VT" links above to verify live.

</details>

---

## Kill Chain Architecture

```
                          DROPPER (WiFi Analyzer Pro)
                               │
                               │ 72h dormancy → config check → payload download
                               ▼
                    STAGE-1-EVASION (SkyWeather Forecast)
                               │
              ┌────────────────┼────────────────┐
              │                │                │
         EVASION          CREDENTIAL         EXFIL
    Anti-debug (3-layer)   A11y capture     DGA fallback
    Anti-emulator (14)     Overlay (2032)   4-stage loader
    Anti-Frida (5-vector)  OTP dual-path    WorkManager beacon
    intArrayOf encoding    ATS auto-fraud   Yamux multiplexer
              │                │                │
              └────────────────┼────────────────┘
                               │
                    OVERLAY-BANKER (Doc Reader Lite)
                         53 modules
              ┌─────────────┬──────────────────┐
              │ STEALER     │ RAT / CONTROL    │
              │ NFC ghost   │ Screen stream    │
              │ Hidden VNC  │ Audio record     │
              │ SOCKS5 proxy│ Camera capture   │
              │ SSO hijack  │ Remote shell     │
              │ TEE offload │ Touch logging    │
              │ SMS worm    │ Factory reset    │
              ├─────────────┼──────────────────┤
              │ EVASION     │ SOCIAL ENGINEER  │
              │ Per-build   │ Call forwarding  │
              │ Behavior    │ Contact inject   │
              │ Anti-*      │ Black screen     │
              │ Play Integ  │ USSD execution   │
              │ Obfuscation │ Auth capture     │
              └─────────────┴──────────────────┘
```

---

## Threat Matrix

Every technique below is **implemented as working code**, sourced from public threat-intel reports on real banker families:

| Technique | Family | Specimen | Source Module |
|---|---|---|---|
| Accessibility abuse + auto-click | Anatsa V4 | overlay-banker, stage-1 | `BankerA11yService.kt` |
| ATS automated transfer | SharkBot V2.8 | stage-1 | `AtsEngine.kt` |
| TYPE_ACCESSIBILITY_OVERLAY (2032) | Anatsa 2025+ | both | `A11yOverlay2032.kt` |
| NLS + SMS dual OTP capture | Anatsa + SharkBot | both | `OtpNotifService.kt`, `SmsInterceptor.kt` |
| DGA (MD5+Calendar) | SharkBot V2.8 | both | `Dga.kt`, `DomainResolver.kt` |
| 4-stage modular loader | Anatsa V4 | both | `ModularLoader.kt`, `PayloadManager.kt` |
| Hidden VNC (MediaProjection) | Klopatra | overlay-banker | `HiddenVnc.kt` |
| Yamux multiplexed C2 | Klopatra + Mirax | overlay-banker | `YamuxProxy.kt` |
| SOCKS5 residential proxy | Mirax | overlay-banker | `ResidentialProxy.kt` |
| NFC ghost-tap relay | RatOn | overlay-banker | `NfcRelay.kt` |
| SSO hijack + MFA auto-approve | Vespertine | overlay-banker | `SsoHijacker.kt` |
| TEE/TrustZone offload | Drelock | overlay-banker | `TeeOffload.kt` |
| Per-build AI obfuscation | Apex | overlay-banker | `PerBuildObfuscation.kt` |
| Behavior mimicry (log-normal jitter) | Herodotus | both | `BehaviorMimicry.kt` |
| BIP39 seed phrase scraping | Perseus | overlay-banker | `NoteAppScraper.kt` |
| SMS worm spreading | FluBot | overlay-banker | `SmsWorm.kt` |
| Anti-debug (3-layer) | SharkBot | overlay-banker | `AntiDebug.kt` |
| Anti-emulator (14-check) | SharkBot | overlay-banker | `AntiEmulator.kt` |
| Anti-Frida (5-vector) | Anatsa + SharkBot | overlay-banker | `AntiFrida.kt` |
| Native JNI protection | Klopatra (Virbox) | overlay-banker | `NativeProtect.kt` |
| XOR + AES string encryption | Anatsa | overlay-banker | `StringDecoder.kt` |
| Reflection API hiding | Anatsa | overlay-banker | `ReflectionHider.kt` |
| ContentProvider pre-init | Anatsa | overlay-banker | `EarlyInitProvider.kt` |
| WorkManager 15-min beacon | Anatsa | both | `WorkManagerBeacon.kt` |
| MediaProjection auto-consent | Klopatra | overlay-banker | `MediaProjectionAutoConsent.kt` |
| Play Integrity recon | Drelock | overlay-banker | `PlayIntegrityProbe.kt` |
| Screen streaming (MediaProjection→C2) | Brokewell, Albiriox | overlay-banker | `ScreenStreamer.kt` |
| Full keylogging (every input field) | Brokewell, TrickMo | overlay-banker | `BankerA11yService.kt` |
| Audio recording (ambient mic) | Brokewell | overlay-banker | `AudioRecorder.kt` |
| Camera capture (front + rear) | Brokewell, Cerberus | overlay-banker | `CameraCapture.kt` |
| Call forwarding/hijacking (USSD) | FakeCall | overlay-banker | `CallForwarder.kt` |
| Default dialer takeover | FakeCall | overlay-banker | `CallForwarder.kt` |
| Notification suppression | TrickMo, SOVA | overlay-banker | `NotifSuppressor.kt` |
| Google Authenticator TOTP capture | Crocodilus | overlay-banker | `AuthenticatorCapture.kt` |
| Geolocation tracking (GPS+Network) | Brokewell, ToxicPanda | overlay-banker | `GeoTracker.kt` |
| Device reconnaissance beacon | ALL families | overlay-banker | `DeviceRecon.kt` |
| Full touch/gesture logging | Brokewell | overlay-banker | `TouchLogger.kt` |
| Fake contact injection | Crocodilus 2025 | overlay-banker | `ContactInjector.kt` |
| Black screen overlay (RAT mask) | Crocodilus, ToxicPanda | overlay-banker | `BlackScreenOverlay.kt` |
| Remote shell execution | Brokewell, Albiriox | overlay-banker | `RemoteShell.kt` |
| App uninstall (AV removal) | TrickMo, SOVA | overlay-banker | `AppManager.kt` |
| Factory reset (evidence wipe) | BRATA | overlay-banker | `RemoteShell.kt` |

---

## Detection Corpus

Every attack ships with matching detection. 107 rules total:

```
detection/
├── yara/                   24 rules — static APK/DEX scanning
│   ├── banker-shape.yar         Overlay banker multi-vector shape
│   ├── sms-stealer.yar          ContentResolver SMS pattern
│   ├── dropper.yar              Config-then-download shape
│   ├── dga.yar                  MD5+Calendar DGA (SharkBot)
│   ├── dcl-antiforensics.yar    DexClassLoader + file deletion
│   ├── intarray-encoding.yar    Arithmetic string obfuscation
│   ├── frontier.yar             2025-2026 technique shapes
│   ├── rat-capabilities.yar    RAT: camera, audio, TOTP, USSD, wipe, AV-kill
│   └── master.yar               All rules consolidated
│
├── sigma/                  34 rules — runtime behavioral detection
│   ├── sms-contentresolver.yml     SMS access from non-SMS app
│   ├── dropper-download.yml        FG service config + binary download
│   ├── overlay-trigger.yml         A11y → overlay window creation
│   ├── dcl-antiforensics.yml       DexClassLoader + file deletion
│   ├── workmanager-beacon.yml      15-min periodic POST
│   ├── dual-otp-capture.yml        NLS + SMS same package
│   ├── ats-killchain.yml           Gesture injection during banking
│   ├── a11y-overlay-chain.yml      Full overlay trigger pipeline
│   ├── frontier.yml                2025-2026 behavioral patterns
│   ├── rat-behavioral.yml          RAT: camera, audio, screen, TOTP, touch, contacts
│   └── master.yml                  All rules consolidated
│
└── frida/                  48 hooks — dynamic instrumentation
    ├── sms-monitor.js           ContentResolver SMS capture
    ├── network-monitor.js       HTTP/OkHttp exfil intercept
    ├── overlay-monitor.js       WindowManager overlay creation
    ├── dcl-monitor.js           DexClassLoader + DEX capture
    ├── nls-monitor.js           Notification OTP intercept
    ├── dga-monitor.js           MessageDigest DGA detection
    ├── a11y-monitor.js          AccessibilityService dispatch
    ├── ats-monitor.js           Gesture injection + auto-fill
    ├── clipboard-monitor.js     Clipboard polling detection
    ├── evasion-bypass.js        Anti-debug/emulator/Frida defeat
    ├── frontier-monitor.js      2025-2026 technique hooks
    ├── rat-monitor.js           RAT capabilities (camera, audio, screen, TOTP, USSD, shell, wipe)
    └── master-monitor.js        All hooks consolidated (48 hooks)
```

### Run Detection Against Any APK

```bash
# Static scan
yara -r detection/yara/master.yar suspect.apk

# Against Takopii specimens (expect 9+ hits per APK)
yara -r detection/yara/master.yar specimens/overlay-banker/app/build/outputs/apk/release/app-release.apk

# Dynamic monitoring
frida -U -l detection/frida/master-monitor.js -f com.suspect.package

# Sigma rules feed from Frida output or logcat pipeline
```

---

## Documentation (8,352 lines)

| Document | Lines | Audience | What You Get |
|---|---|---|---|
| 📕 [REDTEAM-ANALYSIS.md](docs/REDTEAM-ANALYSIS.md) | 4,025 | Offense | Kill chains, annotated source for all 187 .kt files, evasion architecture, C2 protocols |
| 📘 [BLUETEAM-DETECTION.md](docs/BLUETEAM-DETECTION.md) | 5,457 | Defense | IOCs, 107 detection rules (YARA + Sigma + Frida), network signatures, forensic commands |
| 📗 [VT-EVASION-RESEARCH.md](docs/VT-EVASION-RESEARCH.md) | 949 | Research | 11-round ML classifier defeat journal, build-artifact topology theory |

---

## Quick Start

```bash
# Clone
git clone https://github.com/F2u0a0d3/takopii.git
cd takopii

# Option A: Download pre-built APKs from Releases
# → github.com/F2u0a0d3/takopii/releases

# Option B: Build from source (Android SDK + JDK 17)
cd specimens/sms-stealer && ./gradlew assembleRelease && cd ../..
cd specimens/dropper && ./gradlew assembleRelease && cd ../..
cd specimens/overlay-banker && ./gradlew assembleRelease && cd ../..

# Verify VT score yourself
sha256sum specimens/*/app/build/outputs/apk/release/app-release.apk

# Run detection rules
yara -r detection/yara/master.yar specimens/overlay-banker/app/build/outputs/apk/release/app-release.apk

# Dynamic analysis (rooted emulator + frida-server)
frida -U -l detection/frida/master-monitor.js -f com.docreader.lite
```

---

## Pedagogical Progression

```
    SINGLE SURFACE           MULTI-SURFACE            DELIVERY              FULL KILL CHAIN
  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐
  │  sms-stealer    │   │  overlay-banker  │   │  dropper +      │   │  stage-1-evasion     │
  │                 │   │                  │   │  stage-2-payload │   │                      │
  │  SMS → C2       │   │  A11y → Overlay  │   │  Dormancy →     │   │  Evasion + ATS +     │
  │  1 receiver     │   │  → Exfil         │   │  Download →     │   │  DGA + DCL + Overlay │
  │  3 OTP regexes  │   │  42 modules      │   │  DexClassLoader │   │  14 core modules     │
  └────────┬────────┘   └────────┬────────┘   └────────┬────────┘   └──────────┬──────────┘
           │                     │                     │                       │
           v                     v                     v                       v
     Learn: intercept      Learn: multi-         Learn: delivery         Learn: full
     + OTP extraction      surface wiring        chain + evasion         composition +
                           + overlay UI                                  detection rules
```

---

## Who This Is For

**Detection Engineers** — 66 AV engines scored 0 on specimens implementing ATS, screen streaming, call hijacking, TOTP capture, NFC relay, residential proxy, and 40+ other techniques. The 107 detection rules target behavioral invariants that survive evasion.

**Red Teamers** — The VT evasion research documents how ML classifiers operate on build-artifact topology, not application semantics. 11 rounds of source-level changes had zero effect on VT score.

**Educators** — Progressive complexity from single-surface SMS to full 5-stage kill chain. Each specimen maps to MITRE ATT&CK Mobile techniques.

**RASP Vendors** — TYPE_ACCESSIBILITY_OVERLAY (2032) from a separate app bypasses every surveyed commercial RASP. This gap requires MTD, not RASP alone.

---

## What These Are NOT

These are not random stealers from underground forums.

- **Production-grade architecture** — 37 techniques from 17 documented families, composed into working kill chains
- **Lab-constrained** — C2 = RFC1918/loopback only, no public exfil
- **Research artifacts** — every attack ships with matching detection rules
- **Evasion-validated** — 0/66 VirusTotal is empirical, not theoretical

Safety constraints (loopback C2, own-package filters) are **code-level**, not architecture-level. The architecture is production-grade. See [SECURITY.md](SECURITY.md).

---

## Project Structure

```
takopii/
├── specimens/                    4 specimen APK projects
│   ├── sms-stealer/              53 .kt — Battery Boost Pro
│   ├── overlay-banker/           55 .kt — Doc Reader Lite
│   ├── dropper/                  50 .kt — WiFi Analyzer Pro
│   ├── stage-1-evasion/          42 .kt — SkyWeather Forecast
│   └── stage-2-payload/          1 .java — Recon module DEX
├── docs/                         8,352 lines of analysis
│   ├── REDTEAM-ANALYSIS.md       4,025 lines — offensive analysis
│   ├── BLUETEAM-DETECTION.md     5,457 lines — detection engineering
│   └── VT-EVASION-RESEARCH.md    949 lines — ML evasion research
├── detection/                    107 standalone detection rules
│   ├── yara/                     24 YARA rules (9 files + master)
│   ├── sigma/                    34 Sigma rules (11 files + master)
│   └── frida/                    13 Frida monitors (13 files + master)
├── SECURITY.md                   Safety contract + threat model
├── CONTRIBUTING.md               How to contribute
└── awesome-android-banker-defense.md   Curated resource list
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Priority areas:

- **RASP bypass matrix population** — field-test commercial RASPs against specimens
- **Detection rule improvements** — reduce false positives, add new behavioral patterns
- **New family coverage** — add techniques from emerging 2026+ banker families
- **Translation** — non-English documentation (LatAm, APAC)

---

## References

- OWASP MASTG v1.7.0 / MASVS v2.0.0
- MITRE ATT&CK Mobile
- Cleafy — Anatsa threat reports (2024-2025)
- ThreatFabric — Mirax, Vespertine analysis (2026)
- Zscaler ThreatLabz — SharkBot analysis
- NCC Group — Klopatra VNC analysis
- ESET — Apex polymorphism report (2026)

---

## Star History

If this project helps your research, detection engineering, or education — star it. The detection rules alone are worth the click.

[![Star History Chart](https://api.star-history.com/svg?repos=F2u0a0d3/takopii&type=Date)](https://star-history.com/#F2u0a0d3/takopii&Date)

---

> *The stealer code is real. The detection rules are real. The 0/66 is real. Study it before it studies your users.*
