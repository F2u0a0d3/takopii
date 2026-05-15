# SkyWeather Forecast — Banker Specimen

Standalone dropper-shape APK demonstrating the full Anatsa/SharkBot kill chain.
Functional weather app camouflage with embedded offensive modules gated behind
evasion checks. 1.70 MB signed release, 0/75 VT.

**This is a lab specimen. See [`../../SAFETY.md`](../../SAFETY.md) for the safety contract.**

## Quick Start

```bash
# Build
./gradlew assembleRelease   # R8-minified, 1.66 MB
./gradlew assembleDebug      # unminified, multi-dex, ~7.5 MB

# Install on emulator
adb install app/build/outputs/apk/release/app-release.apk

# Start lab C2 (loopback-only)
python scripts/lab-c2/server.py --port 8080

# Attach Frida master monitor
frida -U com.skyweather.forecast -l scripts/frida/skyweather-monitor.js

# Run YARA detection (extract DEX first — APK is compressed)
unzip -o app/build/outputs/apk/release/app-release.apk classes.dex -d /tmp
yara -r scripts/detection/yara/master.yar /tmp/classes.dex
# Expected: 9 rule hits
```

## Kill Chain (5 Stages)

```
Stage 1: Evasion         intArrayOf obfuscation, anti-debug, DGA, DexClassLoader
Stage 2: Credential       AccessibilityService capture + TYPE_ACCESSIBILITY_OVERLAY
Stage 3: OTP Intercept    NotificationListener + SMS receiver (priority 999)
Stage 4: ATS              Screen reading + gesture injection + OTP auto-fill
Stage 5: Composition      Cross-stage wiring verified, detection rules validated
```

## Directory Layout

```
specimens/stage-1-evasion/
├── app/src/main/kotlin/com/skyweather/forecast/
│   ├── MainActivity.kt              Weather app UI (camouflage)
│   ├── core/
│   │   ├── AppConfig.kt             Encoded endpoints + XOR key + evasion gates
│   │   ├── AccessibilityEngine.kt   A11y event capture + overlay trigger + ATS
│   │   ├── NotificationEngine.kt    NLS OTP intercept
│   │   ├── SmsInterceptor.kt        SMS receiver + OTP extraction
│   │   ├── CredentialStore.kt       Credential buffer + JSON exfil format
│   │   ├── SyncTask.kt              WorkManager C2 beacon + exfil
│   │   ├── UpdateChannel.kt         Config fetch + target list + kill switch
│   │   ├── PayloadManager.kt        XOR decrypt + DexClassLoader + anti-forensics
│   │   ├── DomainResolver.kt        MD5+Calendar DGA (SharkBot V2.8 shape)
│   │   ├── AtsEngine.kt             Command queue + state machine + form fill
│   │   ├── ScreenReader.kt          A11y node traversal + text extraction
│   │   ├── OtpExtractor.kt          Regex OTP extraction + confidence scoring
│   │   ├── OverlayRenderer.kt       TYPE_ACCESSIBILITY_OVERLAY (2032) rendering
│   │   └── GestureInjector.kt       Synthetic tap/swipe with Herodotus jitter
│   └── model/                        Weather data models
├── scripts/
│   ├── detection/
│   │   ├── yara/                     9 YARA rules (7 files + master.yar)
│   │   └── sigma/                    12 Sigma rules (12 files + master.yml)
│   ├── frida/
│   │   ├── skyweather-monitor.js     Master observer (14 hook modules)
│   │   ├── credential-watcher.js     Focused credential flow watcher
│   │   └── ats-watcher.js            Focused ATS execution watcher
│   └── lab-c2/
│       ├── server.py                 Loopback C2 (127.0.0.1 only)
│       ├── generate-test-payload.py  DEX stub + XOR encryptor
│       ├── ats-dvbank-transfer.json  Example ATS commands for DVBank
│       └── README.md                 C2 setup guide
├── SPECIMEN.md                       Full technical analysis (~900 lines)
└── README.md                         This file
```

## Companion Tooling

### Lab C2 Server

```bash
# Basic — receive beacons + credentials
python scripts/lab-c2/server.py

# With staged payload + target list
python scripts/lab-c2/server.py \
  --payload test-payload.enc \
  --targets "com.dvbank.example" \
  --ats-file scripts/lab-c2/ats-dvbank-transfer.json

# Generate test payload stub
python scripts/lab-c2/generate-test-payload.py --stub -o test-payload.enc
```

Binds 127.0.0.1 only (hardcoded). Emulator reaches via 10.0.2.2.

### Frida Observers

| Script | Use When |
|---|---|
| `skyweather-monitor.js` | Full kill chain observation — 14 modules, all surfaces |
| `credential-watcher.js` | Credential flow only — CredentialStore + OTP extraction |
| `ats-watcher.js` | ATS only — command queue + gesture injection + screen reading |

### Detection Rules

| Format | Count | Validated Against |
|---|---|---|
| YARA | 9 rules | Release DEX (9/9 fire) + Debug DEX (8/8 fire) |
| Sigma | 12 rules | Structural (runtime needs logcat/proxy) |
| Frida | 14 modules | Structural (runtime needs attached specimen) |

```bash
# YARA validation
python -c "
import yara, zipfile, tempfile, os
z = zipfile.ZipFile('app/build/outputs/apk/release/app-release.apk')
with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as f:
    f.write(z.read('classes.dex')); p = f.name
for yf in sorted(os.listdir('scripts/detection/yara')):
    if yf.endswith('.yar') and yf != 'master.yar':
        r = yara.compile(filepath=f'scripts/detection/yara/{yf}')
        hits = r.match(p)
        for h in hits: print(f'  [HIT] {h.rule}')
os.unlink(p)
"
```

## C2 Protocol

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/beacon` | POST | Device fingerprint `{"m","s","t"}` + credential exfil `{"c":[...]}` |
| `/api/v1/payload` | GET | XOR-encrypted DEX (key: `SkyWeatherSync24`) |
| `/api/v1/config` | GET | `target_list`, `ats_commands`, `kill` switch, `payload_url` |

## Emulator Setup

```bash
# Android emulator (Google APIs image, not Google Play — needs root)
emulator -avd Pixel_6_API_34

# Push Frida server
adb push frida-server-16.x.x-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify
frida-ps -U | grep skyweather
```

## R8 Behavior

Release build aggressively minifies. Detection-relevant survival:

| Survives R8 | Removed by R8 |
|---|---|
| Manifest-bound class names (5 services) | Internal class names (AtsEngine, CredentialStore, etc.) |
| C2 protocol strings (endpoints, regexes) | Function names (isEndpointSafe, generateFallbacks) |
| Event type taxonomy (overlay_pwd, otp_a11y) | XOR key constant (SkyWeatherSync24) |
| ATS vocabulary (ats_commands, auto_fill_otp) | intArrayOf obfuscation arrays |
| Framework API references (DexClassLoader) | DGA helper names (md5Hex, hashToOctets) |
| Anti-debug strings (TracerPid, /proc/self/status) | Overlay type constant (2032 — inlined) |

YARA rules target surviving runtime constants, not structural names.

## References

- [`SPECIMEN.md`](SPECIMEN.md) — full technical analysis
- [`../../ANALYSIS.md`](../../ANALYSIS.md) — hub document (curriculum context)
- [`../../SAFETY.md`](../../SAFETY.md) — lab gate contract
- [`../../research/02-anatsa-threat-intel.md`](../../research/02-anatsa-threat-intel.md) — Anatsa kill chain model
- [`../../research/06-sharkbot-threat-intel.md`](../../research/06-sharkbot-threat-intel.md) — SharkBot ATS + DGA
