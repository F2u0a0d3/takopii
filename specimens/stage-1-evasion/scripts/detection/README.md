# SkyWeather Forecast — Detection Rules

Static + behavioral + dynamic detection corpus for the SkyWeather banker specimen.

## YARA (Static)

**Target:** Extracted `classes.dex` from APK (not raw APK — DEX is DEFLATE-compressed inside ZIP).

```bash
# Extract + scan
unzip -o app-release.apk classes.dex -d /tmp
yara -r yara/master.yar /tmp/classes.dex
```

| File | Rule | Severity | Signal |
|---|---|---|---|
| `skyweather-banker-shape.yar` | `SkyWeather_Banker_Shape` | critical | Composite 4-of-6 category threshold |
| `anatsa-c2-protocol.yar` | `SkyWeather_C2_Protocol` | critical | Beacon + config + payload + exfil |
| `anatsa-c2-protocol.yar` | `SkyWeather_Config_Regex_Pack` | high | 3+ C2 config field names |
| `sms-otp-stealing.yar` | `SkyWeather_SMS_OTP_Stealing` | critical | SMS receiver + OTP event types |
| `dcl-reflection-chain.yar` | `SkyWeather_DCL_Payload_Chain` | critical | DexClassLoader + payload cache |
| `ats-gesture-injection.yar` | `SkyWeather_ATS_Gesture_Injection` | critical | ATS command vocabulary |
| `credential-exfil-taxonomy.yar` | `SkyWeather_Credential_Taxonomy` | critical | Multi-vector event type taxonomy |
| `credential-exfil-taxonomy.yar` | `SkyWeather_Overlay_Credential_Capture` | high | Overlay pwd/usr + renderer |
| `dga-domain-rotation.yar` | `SkyWeather_DGA_Domain_Rotation` | high | MD5 + Calendar + anti-debug + beacon |

**Validated:** 9/9 fire on release DEX, 8/8 fire on debug `classes3.dex`.

Multi-dex note: Debug APK has 10 DEX files. Specimen code in `classes3.dex` (130KB). Scan all `classes*.dex` for debug builds.

## Sigma (Behavioral)

**Target:** Logcat streams, proxy logs, Frida monitor output, specimen telemetry.

| File | Phase | Trigger |
|---|---|---|
| `skyweather-anatsa-killchain.yml` | Full chain | Beacon + config + payload + exfil in 30m |
| `skyweather-workmanager-c2-poll.yml` | Persistence | 15-min SyncTask + same-dest HTTP |
| `skyweather-dcl-anti-forensics.yml` | Execution | DEX write + load + delete in 5m |
| `skyweather-overlay-credential-capture.yml` | Credential | TYPE_ACCESSIBILITY_OVERLAY (2032) |
| `skyweather-nls-otp-intercept.yml` | Credential | NLS + OTP pattern extraction |
| `skyweather-sms-otp-exfil.yml` | Collection | SMS → OTP → C2 exfil |
| `skyweather-permission-escalation.yml` | Priv Esc | A11y + NLS + SMS grant in 1h |
| `skyweather-ats-form-fill.yml` | ATS | Target foreground + SET_TEXT |
| `skyweather-ats-otp-autofill.yml` | ATS | OTP intercept + auto-inject in 5m |
| `skyweather-accessibility-abuse.yml` | Collection | A11y volume + cross-package read |
| `skyweather-modular-loader.yml` | Execution | Config + download + DCL + cleanup |
| `skyweather-update-channel.yml` | C2 | Config poll + target/ATS updates |

## Validation

```bash
# YARA — requires yara-python
pip install yara-python
python -c "
import yara, zipfile, tempfile, os
z = zipfile.ZipFile('../../app/build/outputs/apk/release/app-release.apk')
with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as f:
    f.write(z.read('classes.dex')); p = f.name
total = 0
for yf in sorted(os.listdir('yara')):
    if yf.endswith('.yar') and yf != 'master.yar':
        r = yara.compile(filepath=f'yara/{yf}')
        for h in r.match(p):
            total += 1; print(f'[HIT] {h.rule}')
os.unlink(p)
print(f'Total: {total} rules fired')
"
```
