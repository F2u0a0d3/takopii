# Blue Team Detection Guide — Takopii Specimen APKs

> Detection engineering reference for 4 Android banker-malware specimens. Covers IOCs, static indicators, behavioral signatures, YARA rules, Sigma rules, Frida hooks, network signatures, and runtime forensics commands. Every detection targets behavioral invariants that survived 11 rounds of evasion iteration — build-artifact-based detection is explicitly called out as brittle.

### Companion Documents

| Doc | Lines | Purpose |
|---|---|---|
| [`REDTEAM-ANALYSIS.md`](REDTEAM-ANALYSIS.md) | RED | Offensive analysis — annotated source, kill chains, family parallels |
| **→ You are here** | **BLUE** | Detection engineering — IOCs, YARA, Sigma, Frida hooks |
| [`VT-EVASION-RESEARCH.md`](VT-EVASION-RESEARCH.md) | VT | 11-round ML classifier defeat journal |

### Standalone Detection Rules (runnable — extracted from this doc)

All rules referenced in this document are also available as standalone runnable files:

```
../detection/yara/master.yar          — 24 YARA rules: yara -r master.yar <target.apk>
../detection/sigma/master.yml         — 34 Sigma rules: sigmac -t splunk master.yml
../detection/frida/master-monitor.js  — 37 Frida hooks: frida -U -l master-monitor.js -f <pkg>
```

Individual rule files in `../detection/yara/`, `../detection/sigma/`, `../detection/frida/`.

---

## Quick Reference — IOCs

### SHA256 Hashes

```
sms-stealer:      32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243
dropper:          254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed
stage-1-evasion:  af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612
overlay-banker:   33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0
```

### Stage-2 Payload Hashes (delivered by dropper)

```
stage-2 DEX:      189701be62be8b20fe43eb3b35ac7525f2b2313951122fb7182137a199944098  (classes.dex)
stage-2 payload:  81926b22a9c96cbe63c7b0c66724b01916dcdfd29681d9f02a5f0a2d1f317e79  (payload.enc — XOR-encrypted)
XOR key:          SkyWeatherSync24  (embedded in dropper — see specimens/stage-2-payload/scripts/build-payload.py)
```

### Package Names

```
com.cleanmaster.battery     (sms-stealer)
com.wifianalyzer.pro        (dropper)
com.skyweather.forecast     (stage-1-evasion)
com.docreader.lite          (overlay-banker)
```

### C2 Endpoints

```
http://10.0.2.2:8080/api/v1/sync          (sms-stealer — exfil)
http://10.0.2.2:8080/api/v1/backup        (sms-stealer — backup exfil)
http://10.0.2.2:8081/api/v1/check         (dropper — config check)
http://10.0.2.2:8081/api/v1/payload       (dropper — payload download)
http://10.0.2.2:8080/api/v1/beacon        (stage-1-evasion — periodic beacon)
http://10.0.2.2:8080/api/v1/config        (stage-1-evasion — config fetch)
http://10.0.2.2:8080/api/v1/payload       (stage-1-evasion — DCL payload)
http://10.0.2.2:8080/api/v1/register      (overlay-banker — bot registration)
http://10.0.2.2:8080/api/v1/commands      (overlay-banker — C2 poll)
http://10.0.2.2:8080/api/v1/exfil         (overlay-banker — batch exfil)
```

### Application Labels

```
Battery Boost Pro        (sms-stealer)
WiFi Analyzer Pro        (dropper)
SkyWeather               (stage-1-evasion)
Doc Reader Lite          (overlay-banker)
```

---

## Manifest-Based Detection (Static Triage)

### Permission Combinations

**SMS-Stealer Shape:**
```
READ_SMS + INTERNET + FOREGROUND_SERVICE + RECEIVE_BOOT_COMPLETED
```
Note: `RECEIVE_SMS` was removed in Round 10 evasion — specimen uses `ContentResolver` instead of `BroadcastReceiver`. Detection should key on `READ_SMS` + network + persistence, not `RECEIVE_SMS`.

**Dropper Shape:**
```
INTERNET + ACCESS_NETWORK_STATE + FOREGROUND_SERVICE + FOREGROUND_SERVICE_DATA_SYNC
```
Minimal permissions. Hard to distinguish from legitimate utility apps by permissions alone.

**Full Banker Shape (overlay-banker):**
```
INTERNET + READ_SMS + RECEIVE_SMS + FOREGROUND_SERVICE + FOREGROUND_SERVICE_SPECIAL_USE
+ POST_NOTIFICATIONS + RECEIVE_BOOT_COMPLETED + QUERY_ALL_PACKAGES + NFC
+ FOREGROUND_SERVICE_MEDIA_PROJECTION
```
High-confidence banker: `BIND_ACCESSIBILITY_SERVICE` + `NOTIFICATION_LISTENER_SERVICE` + `RECEIVE_SMS` + `QUERY_ALL_PACKAGES` + `FOREGROUND_SERVICE_SPECIAL_USE`. Five-permission combo is rare in legitimate apps.

**SkyWeather Shape:**
```
INTERNET + RECEIVE_SMS + READ_SMS + ACCESS_FINE_LOCATION + FOREGROUND_SERVICE
+ RECEIVE_BOOT_COMPLETED
```
Weather app claiming SMS permissions = suspicious. Location is plausible for weather; SMS is not.

### Component Indicators

**High-confidence signals:**

| Component Pattern | Specimen | Confidence |
|---|---|---|
| AccessibilityService declaration | overlay-banker, stage-1-evasion | HIGH |
| NotificationListenerService declaration | overlay-banker, stage-1-evasion | HIGH |
| SMS_RECEIVED intent-filter (priority) | overlay-banker, stage-1-evasion | HIGH |
| `foregroundServiceType="specialUse"` | overlay-banker | HIGH |
| NFC HCE Service declaration | overlay-banker | MEDIUM |
| ContentProvider pre-Application init | overlay-banker (`EarlyInitProvider`) | MEDIUM |
| `foregroundServiceType="dataSync"` | sms-stealer, dropper | LOW (common) |

### Manifest Grep Commands

```bash
# Banker-shape permission combo
aapt dump badging suspect.apk | grep -E "ACCESSIBILITY|NOTIFICATION_LISTENER|RECEIVE_SMS|QUERY_ALL_PACKAGES"

# Foreground service types
aapt dump xmltree suspect.apk AndroidManifest.xml | grep -i "foregroundServiceType"

# High-priority SMS receiver
aapt dump xmltree suspect.apk AndroidManifest.xml | grep -B5 "SMS_RECEIVED"

# AccessibilityService + NLS declarations
aapt dump xmltree suspect.apk AndroidManifest.xml | grep -E "AccessibilityService|NotificationListenerService"

# BOOT_COMPLETED receiver (persistence)
aapt dump xmltree suspect.apk AndroidManifest.xml | grep -B3 "BOOT_COMPLETED"

# ContentProvider with no authorities (init hook pattern)
aapt dump xmltree suspect.apk AndroidManifest.xml | grep -A5 "provider"
```

---

## DEX-Level Static Detection

### String Pool Indicators

Note: SMS-stealer and dropper externalized sensitive strings to `strings.xml` (resources.arsc). DEX string pool scanning misses these. Always scan BOTH DEX + resources.arsc.

**SMS-Stealer (resources.arsc, not DEX):**
```
content          (R.string.content_scheme)
sms              (R.string.content_auth)
inbox            (R.string.content_path)
address          (R.string.col_a)
body             (R.string.col_b)
date             (R.string.col_c)
/api/v1/sync     (R.string.sync_url)
```

**Dropper (resources.arsc, not DEX):**
```
/api/v1/check             (R.string.config_url)
X-App-Version             (R.string.version_header)
X-Device                  (R.string.device_header)
application/octet-stream  (R.string.cache_type)
wifi_db_cache.dat         (R.string.cache_file)
```

**SkyWeather (DEX string pool — `intArrayOf` XOR encoded):**
```
# Encoded as integer arrays — invisible to string scanning
# Detection requires pattern matching on intArrayOf initialization
# with subsequent subtraction decode loop

# Decoded values (not scannable without execution):
#   http://10.0.2.2:8080/api/v1/beacon
#   SkyWeatherSync24 (XOR key)
#   payload.Module (DCL target class)
#   execute (reflective method name)
```

**Overlay-Banker (DEX string pool — partial intArrayOf encoded):**
```
# Encoded strings (C2 endpoints, headers):
#   /api/v1/exfil, /api/v1/register, /api/v1/commands
#   application/json, X-Bot-Id

# Unencoded (visible in DEX — OkHttp class names survive):
stealer                  (package namespace)
BankerA11yService        (class name)
OtpNotifService          (class name)
OverlayAttack            (class name)
StealthFgService         (class name)
```

### Resource.arsc Scanning

```bash
# Extract and scan strings.xml from APK
unzip -p suspect.apk resources.arsc | strings | grep -iE "sms|inbox|content://|api/v1|otp|credential"

# More precise — decode with aapt
aapt dump resources suspect.apk | grep -iE "sms|inbox|otp|sync|beacon|payload|credential"

# For Takopii specimens specifically
aapt dump resources suspect.apk | grep -E "content_scheme|content_auth|content_path|col_a|col_b|col_c|sync_url|config_url"

# Detect intArrayOf encoding pattern in smali
# Extract classes.dex, baksmali to smali, grep for:
baksmali d classes.dex -o smali_out
grep -rn "new-array.*I" smali_out/ | awk -F: '{print $1}' | sort -u | head -20
# High intArrayOf density in small classes = potential encoded strings
```

### intArrayOf Detection Heuristic

```bash
# Count integer array initializations per class
# Legitimate apps: 0-3 per class. Encoded-string classes: 10+
for smali in smali_out/com/skyweather/forecast/core/*.smali; do
    count=$(grep -c "new-array.*I" "$smali")
    if [ "$count" -gt 5 ]; then
        echo "SUSPECT: $smali ($count intArrayOf patterns)"
    fi
done
```

---

## Behavioral Detection (Runtime)

### Call-Chain Signatures

These behavioral patterns survived all 11 rounds of evasion. They are the durable detection surface.

**Pattern 1: SMS ContentResolver Read + HTTP POST (sms-stealer)**
```
ContentResolver.query(content://sms/inbox, [address, body, date], ...)
    -> JSONObject construction with collected data
    -> HttpURLConnection POST to external host
```
Detection: Sigma rule on ContentResolver SMS query followed by network POST within 60s from non-SMS app.

**Pattern 2: ForegroundService Config Check + Payload Download (dropper)**
```
ForegroundService.startForeground(...)
    -> HttpURLConnection GET to /api/v1/check
    -> JSON parse {"ok": true, "url": "..."}
    -> HttpURLConnection GET (payload download)
    -> File.writeBytes(payload)
```
Detection: Sigma rule on foreground service network activity with sequential GET (config) + GET (binary download) pattern.

**Pattern 3: Accessibility Event -> Overlay Trigger (overlay-banker, stage-1-evasion)**
```
AccessibilityService.onAccessibilityEvent(TYPE_WINDOW_STATE_CHANGED)
    -> packageName match against target list
    -> WindowManager.addView(TYPE_ACCESSIBILITY_OVERLAY or TYPE_APPLICATION_OVERLAY)
```
Detection: Frida hook on `WindowManager.addView()` with overlay window type from non-foreground package.

**Pattern 4: NLS + SMS Dual OTP Capture (overlay-banker, stage-1-evasion)**
```
NotificationListenerService.onNotificationPosted()
    -> Notification text regex (OTP/code/PIN patterns)

BroadcastReceiver.onReceive(SMS_RECEIVED)
    -> SmsMessage.createFromPdu()
    -> OTP regex extraction
```
Detection: Sigma rule on NLS notification read + SMS receive from same package within 10-minute window.

**Pattern 5: WorkManager Periodic Beacon (stage-1-evasion, overlay-banker)**
```
WorkManager.enqueueUniquePeriodicWork(interval=15min)
    -> HttpURLConnection POST to C2 beacon endpoint
    -> Response: config update / new target list / kill switch
```
Detection: Sigma rule on periodic network calls at ~15min interval from background app.

**Pattern 6: DexClassLoader + File Deletion (stage-1-evasion)**
```
HttpURLConnection.GET(payload_url) -> write .cache_data
    -> XOR decrypt -> write .update_cache.dex
    -> DexClassLoader($new(dex_path, ...))
    -> Class.forName(decoded_name) -> method.invoke()
    -> File.delete(.cache_data)
    -> File.delete(.update_cache.dex)
    -> File.delete(.oat_cache/*)
```
Detection: Frida hook on DexClassLoader.$init capturing DEX bytes before deletion. Sigma rule on DCL instantiation + file deletion within 30s.

**Pattern 7: Batch Exfiltration Flush (overlay-banker)**
```
ConcurrentLinkedQueue.size >= 5 OR timer >= 20s
    -> JSONArray batch construction (credential + otp + keystroke + clipboard + sms + event)
    -> OkHttp POST /api/v1/exfil with bot_id + batch array
    -> On failure: re-queue for next flush cycle
```
Detection: Network signature on batch JSON with mixed data-type array to single endpoint.

**Pattern 8: ATS Gesture Injection During Banking Session (stage-1-evasion)**
```
AccessibilityEngine detects target banking app foreground
    -> AtsEngine.onTargetForegrounded() (1500ms render delay)
    -> GestureInjector.setText() (3-step: focus -> clear -> set) on amount field
    -> GestureInjector.clickNode() on "Continue" button
    -> wait_screen for OTP prompt (pattern: "code"/"verification")
    -> CredentialStore.peekAll() -> find latest OTP entry (Stage 3 bridge)
    -> GestureInjector.setText() fills intercepted OTP into verification field
    -> GestureInjector.clickNode() on "Confirm"
    -> GestureInjector.pressHome() — hides confirmation from user
    -> SyncTask.scheduleUrgent() — report ATS result to C2
```
Detection: Multi-event Sigma correlation — A11y foreground change + ACTION_SET_TEXT + dispatchGesture + OTP query from CredentialStore within 60s during banking app session. 60s timeout, 3 retries per command, Herodotus jitter (300-3000ms uniform) between actions.

**Pattern 9: Clipboard Polling from AccessibilityService (overlay-banker)**
```
BankerA11yService.onServiceConnected()
    -> handler.postDelayed(pollClipboard, 2500ms)
    -> ClipboardManager.getPrimaryClip() every 2.5 seconds
    -> Diff against lastClip
    -> Exfil.clipboard(content) on change
```
Detection: Frida hook on ClipboardManager.getPrimaryClip() — stack trace containing AccessibilityService = Path 2 clipper (bypasses Android 10+ background clipboard restriction).

**Pattern 10: A11y Overlay Trigger Chain (overlay-banker)**
```
BankerA11yService.onWindowChanged(TYPE_WINDOW_STATE_CHANGED)
    -> MediaProjectionAutoConsent check (Klopatra pattern)
    -> systemUI filter
    -> currentForeground update
    -> NoteAppScraper.scrapeForSeeds() if note app (Perseus pattern)
    -> SsoHijacker.autoApprove() if SSO app (200ms delay, Vespertine pattern)
    -> Targets.match(pkg) -> OverlayAttack.show() or A11yOverlay2032.showLoginOverlay()
      (500ms delay — waits for banking app to render before overlay)
```
Detection: Sigma rule on TYPE_WINDOW_STATE_CHANGED from non-system package → WindowManager.addView with overlay window type within 5s. The 500ms delay between detection and overlay is a detectable timing signature.

---

## YARA Rules

**Note on `is_apk`:** The `is_apk` condition used below requires YARA's `androguard` module or a custom `is_apk` rule. Alternative: use `uint32(0) == 0x04034B50` (ZIP magic) + filename pattern. For resources.arsc scanning, extract first, then run YARA against extracted files.

### Rule 1: SMS ContentResolver Pattern (catches sms-stealer)

```yara
import "androguard"

rule Takopii_SMS_ContentResolver_Pattern {
    meta:
        description = "Detects SMS data access via ContentResolver with generic key exfiltration"
        author = "Takopii Framework"
        severity = "high"
        specimen = "sms-stealer"
        mitre = "T1582"

    strings:
        $cr_query = "content://sms" ascii wide
        $cr_inbox = "inbox" ascii wide
        $col_addr = "address" ascii wide
        $col_body = "body" ascii wide
        $col_date = "date" ascii wide
        $json_obj = "JSONObject" ascii
        $http_post = "HttpURLConnection" ascii
        // Resource-externalized variants
        $res_scheme = "content_scheme" ascii wide
        $res_auth = "content_auth" ascii wide

    condition:
        androguard.package_name(/com\.\w+\.\w+/) and
        (
            ($cr_query or ($cr_inbox and 2 of ($col_addr, $col_body, $col_date))) or
            ($res_scheme and $res_auth)
        ) and
        ($json_obj or $http_post)
}
```

For environments without `androguard` module:
```yara
rule Takopii_SMS_ContentResolver_Pattern_NoModule {
    meta:
        description = "Detects SMS stealer pattern (no androguard dependency)"
        author = "Takopii Framework"
        severity = "high"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $cr_query = "content://sms" ascii wide
        $res_scheme = "content_scheme" ascii wide
        $res_auth = "content_auth" ascii wide
        $http_post = "HttpURLConnection" ascii

    condition:
        $zip_magic at 0 and
        ($cr_query or ($res_scheme and $res_auth)) and
        $http_post
}
```

Note: For specimens with string externalization, scan `resources.arsc` not just `classes.dex`. Extract with:
```bash
unzip suspect.apk resources.arsc -d /tmp && yara -r rules.yar /tmp/resources.arsc
```

### Rule 2: Dropper Config-Then-Download Pattern

```yara
rule Takopii_Dropper_Config_Download {
    meta:
        description = "Detects dropper config check + payload download pattern"
        author = "Takopii Framework"
        severity = "high"
        specimen = "dropper"
        mitre = "T1437"

    strings:
        $cfg_check = "/api/v1/check" ascii wide
        $cfg_alt = "config_url" ascii wide
        $http_conn = "HttpURLConnection" ascii
        $fetch_bytes = "fetchBytes" ascii
        $write_bytes = "writeBytes" ascii
        $json_ok = "\"ok\"" ascii
        $octet_stream = "application/octet-stream" ascii wide

    condition:
        uint32(0) == 0x04034B50 and
        ($cfg_check or $cfg_alt) and
        $http_conn and
        ($fetch_bytes or $write_bytes or $octet_stream) and
        $json_ok
}
```

### Rule 3: Overlay Banker Shape

```yara
rule Takopii_Overlay_Banker_Shape {
    meta:
        description = "Detects overlay banker with A11y + NLS + SMS multi-vector"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1626"

    strings:
        $a11y_service = "AccessibilityService" ascii
        $a11y_event = "onAccessibilityEvent" ascii
        $nls = "NotificationListenerService" ascii
        $overlay_type = "TYPE_APPLICATION_OVERLAY" ascii
        $overlay_2032 = "TYPE_ACCESSIBILITY_OVERLAY" ascii
        $window_mgr = "WindowManager" ascii
        $add_view = "addView" ascii
        $sms_received = "SMS_RECEIVED" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $a11y_service and $a11y_event and
        ($overlay_type or $overlay_2032) and
        $window_mgr and $add_view and
        ($nls or $sms_received)
}
```

### Rule 4: DGA Shape (SharkBot V2.8)

```yara
rule Takopii_DGA_MD5_Calendar {
    meta:
        description = "Detects MD5+Calendar DGA pattern (SharkBot V2.8 shape)"
        author = "Takopii Framework"
        severity = "high"
        specimen = "stage-1-evasion"
        mitre = "T1437"

    strings:
        $md5 = "MessageDigest" ascii
        $md5_algo = "MD5" ascii
        $calendar = "Calendar" ascii
        $week = "WEEK_OF_YEAR" ascii
        $tld_xyz = ".xyz" ascii
        $tld_live = ".live" ascii
        $tld_top = ".top" ascii
        // Lab variant: IP generation instead of domain
        $hash_to = "hashToOctets" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $md5 and $md5_algo and $calendar and $week and
        (2 of ($tld_xyz, $tld_live, $tld_top) or $hash_to)
}
```

### Rule 5: Resource-Externalized SMS Stealer

```yara
rule Takopii_Resource_SMS_Stealer {
    meta:
        description = "Detects SMS stealer with URI components externalized to resources"
        author = "Takopii Framework"
        severity = "high"
        note = "Scan resources.arsc, not classes.dex"

    strings:
        $scheme = "content_scheme" ascii wide
        $auth = "content_auth" ascii wide
        $path = "content_path" ascii wide
        $col_a = "col_a" ascii wide
        $col_b = "col_b" ascii wide

    condition:
        $scheme and $auth and $path and ($col_a or $col_b)
}
```

### Rule 6: DexClassLoader Anti-Forensics Pattern

```yara
rule Takopii_DCL_AntiForensics {
    meta:
        description = "Detects DexClassLoader with file deletion (payload load + cleanup)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "stage-1-evasion"
        mitre = "T1407"

    strings:
        $dcl = "DexClassLoader" ascii
        $class_forname = "Class.forName" ascii
        $get_method = "getDeclaredMethod" ascii
        $invoke = ".invoke(" ascii
        $file_delete = ".delete()" ascii
        $cache_data = ".cache_data" ascii
        $update_cache = ".update_cache" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $dcl and
        ($class_forname or $get_method) and
        $file_delete and
        ($cache_data or $update_cache)
}
```

### Rule 7: intArrayOf String Encoding Pattern

```yara
rule Takopii_IntArray_String_Encoding {
    meta:
        description = "Detects arithmetic-shift string encoding via integer arrays"
        author = "Takopii Framework"
        severity = "medium"
        specimen = "stage-1-evasion"
        note = "Heuristic — may FP on apps with heavy integer data. Combine with other rules."

    strings:
        // Common pattern: multiple intArrayOf followed by decode function
        $intarray = "intArrayOf" ascii
        $shift = "SHIFT" ascii
        $tochar = ".toChar()" ascii
        $decode = "decode" ascii
        $chararray = "CharArray" ascii

    condition:
        uint32(0) == 0x04034B50 and
        #intarray > 5 and
        $shift and $tochar and ($decode or $chararray)
}
```

---

## Sigma Rules

### Rule 1: SMS ContentResolver Query from Non-SMS App

```yaml
title: SMS ContentResolver Access from Non-Messaging App
id: takopii-sms-contentresolver-001
status: experimental
description: Detects content://sms/inbox query from app not in default SMS handler list
logsource:
    product: android
    category: content_resolver
detection:
    selection:
        uri|contains: 'content://sms'
        caller_package|not:
            - 'com.google.android.apps.messaging'
            - 'com.samsung.android.messaging'
            - 'com.android.mms'
    condition: selection
level: high
tags:
    - attack.collection
    - attack.t1582
falsepositives:
    - Backup apps with legitimate SMS backup functionality
    - Parental control apps
```

### Rule 2: ForegroundService Sequential Network Pattern (Dropper)

```yaml
title: ForegroundService Config Check Then Binary Download
id: takopii-dropper-config-download-001
status: experimental
description: Detects foreground service performing config check followed by binary download
logsource:
    product: android
    category: network
detection:
    config_check:
        method: 'GET'
        url|contains: '/api/v1/check'
    payload_download:
        method: 'GET'
        content_type|contains: 'application/octet-stream'
    timeframe: 60s
    condition: config_check | payload_download
level: high
tags:
    - attack.command_and_control
    - attack.t1437
```

### Rule 3: Accessibility Overlay Trigger

```yaml
title: Accessibility Service Overlay Window Creation
id: takopii-overlay-trigger-001
status: experimental
description: Detects WindowManager.addView with overlay window type from AccessibilityService context
logsource:
    product: android
    category: accessibility
detection:
    selection:
        event_type: 'TYPE_WINDOW_STATE_CHANGED'
    overlay_creation:
        api_call: 'WindowManager.addView'
        window_type|contains:
            - 'TYPE_APPLICATION_OVERLAY'
            - 'TYPE_ACCESSIBILITY_OVERLAY'
    timeframe: 5s
    condition: selection | overlay_creation
level: critical
tags:
    - attack.credential_access
    - attack.t1626
```

### Rule 4: DexClassLoader Load + File Deletion (Anti-Forensics)

```yaml
title: DexClassLoader Instantiation Followed by File Deletion
id: takopii-dcl-antiforensics-001
status: experimental
description: Detects DexClassLoader loading external DEX followed by source file deletion within 30 seconds
logsource:
    product: android
    category: runtime
detection:
    dcl_load:
        api_call: 'dalvik.system.DexClassLoader.<init>'
    file_delete:
        api_call: 'java.io.File.delete'
        path|contains:
            - '.dex'
            - '.cache_data'
            - '.update_cache'
            - '.oat_cache'
    timeframe: 30s
    condition: dcl_load | file_delete
level: critical
tags:
    - attack.defense_evasion
    - attack.t1407
falsepositives:
    - Hot-fix frameworks (Tinker, Robust) — rare on banking apps
```

### Rule 5: WorkManager 15-Minute Periodic Beacon

```yaml
title: WorkManager Periodic Network Beacon at Minimum Interval
id: takopii-workmanager-beacon-001
status: experimental
description: Detects WorkManager periodic work with minimum interval (15 min) paired with network POST
logsource:
    product: android
    category: jobscheduler
detection:
    periodic_work:
        api_call: 'WorkManager.enqueueUniquePeriodicWork'
        interval|lte: 900000
    network_post:
        method: 'POST'
        caller_is_background: true
    timeframe: 120s
    condition: periodic_work | network_post
level: high
tags:
    - attack.command_and_control
    - attack.t1437
falsepositives:
    - Analytics SDKs with periodic sync (Firebase, Amplitude)
    - Weather apps with background refresh — check permission combo
```

### Rule 6: Dual OTP Capture (NLS + SMS from Same Package)

```yaml
title: Notification Listener and SMS Receiver in Same Package
id: takopii-dual-otp-capture-001
status: experimental
description: Detects app with both NLS and SMS receiver actively processing in same time window
logsource:
    product: android
    category: notification
detection:
    nls_read:
        api_call: 'NotificationListenerService.onNotificationPosted'
    sms_receive:
        api_call: 'BroadcastReceiver.onReceive'
        intent_action: 'android.provider.Telephony.SMS_RECEIVED'
    same_package: true
    timeframe: 600s
    condition: nls_read and sms_receive
level: critical
tags:
    - attack.collection
    - attack.t1517
```

### Rule 7: ATS Kill Chain Correlation

```yaml
title: Automatic Transfer System Kill Chain — Gesture Injection During Banking Session
id: takopii-ats-killchain-001
status: experimental
description: |
    Detects ATS (Automatic Transfer System) by correlating multiple events during
    banking app foreground session: accessibility text capture + synthetic gesture
    injection + OTP field fill. The canonical banker endgame — automated fraud.
logsource:
    product: android
    category: accessibility
detection:
    banking_foreground:
        event_type: 'TYPE_WINDOW_STATE_CHANGED'
        package|contains:
            - 'bank'
            - 'finance'
            - 'payment'
    text_injection:
        api_call: 'AccessibilityNodeInfo.performAction'
        action: 'ACTION_SET_TEXT'
    gesture_dispatch:
        api_call: 'AccessibilityService.dispatchGesture'
        caller_is_foreground: false
    otp_drain:
        api_call|contains: 'CredentialStore.peek'
    timeframe: 60s
    condition: banking_foreground and (text_injection or gesture_dispatch) and otp_drain
level: critical
tags:
    - attack.fraud
    - attack.t1626
falsepositives:
    - Accessibility testing frameworks (Espresso, UIAutomator) — non-production only
    - Password managers with A11y autofill — check source package against known PMs
```

### Rule 8: Accessibility Service Overlay Trigger Chain

```yaml
title: A11y Service Foreground Detection to Overlay Creation Pipeline
id: takopii-a11y-overlay-chain-001
status: experimental
description: |
    Detects the full BankerA11yService overlay trigger chain:
    TYPE_WINDOW_STATE_CHANGED → package match → WindowManager.addView with overlay type.
    Includes 200-500ms delay pattern between foreground detection and overlay creation.
logsource:
    product: android
    category: accessibility
detection:
    foreground_change:
        event_type: 'TYPE_WINDOW_STATE_CHANGED'
        source_package|not:
            - 'com.android.systemui'
            - 'com.android.launcher'
    overlay_creation:
        api_call: 'WindowManager.addView'
        window_type|contains:
            - 'TYPE_APPLICATION_OVERLAY'
            - 'TYPE_ACCESSIBILITY_OVERLAY'
        creator_package|not: foreground_change.source_package
    keylog_start:
        event_type: 'TYPE_VIEW_TEXT_CHANGED'
        listener_package: overlay_creation.creator_package
    timeframe: 5s
    condition: foreground_change | (overlay_creation or keylog_start)
level: critical
tags:
    - attack.credential_access
    - attack.t1626
    - attack.t1517
```

---

## Frida Hooks

### Hook 1: ContentResolver SMS Monitor

```javascript
// Catches sms-stealer's DataCollector.collectRecentItems()
// and overlay-banker's SMS reads
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
        '[Ljava.lang.String;', 'java.lang.String'
    ).implementation = function(uri, proj, sel, selArgs, sort) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
            console.log("[ALERT] SMS ContentResolver query from: " +
                Java.use("android.app.ActivityThread").currentApplication()
                    .getApplicationContext().getPackageName());
            console.log("  URI: " + uriStr);
            console.log("  Projection: " + (proj ? proj.join(", ") : "null"));
            console.log("  Sort: " + sort);
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.query(uri, proj, sel, selArgs, sort);
    };
});
```

### Hook 2: HttpURLConnection POST Monitor

```javascript
// Catches DataReporter.sendReport() and all HttpURLConnection-based exfil
Java.perform(function() {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var URL = Java.use("java.net.URL");

    URL.$init.overload('java.lang.String').implementation = function(url) {
        console.log("[NET] URL created: " + url);
        return this.$init(url);
    };

    HttpURLConnection.setRequestMethod.implementation = function(method) {
        console.log("[NET] HTTP " + method + " -> " + this.getURL().toString());
        return this.setRequestMethod(method);
    };

    HttpURLConnection.getOutputStream.implementation = function() {
        console.log("[EXFIL] POST body being written to: " + this.getURL().toString());
        return this.getOutputStream();
    };

    // Capture response codes for dropper config check pattern
    HttpURLConnection.getResponseCode.implementation = function() {
        var code = this.getResponseCode();
        console.log("[NET] Response " + code + " from " + this.getURL().toString());
        return code;
    };
});
```

### Hook 3: WindowManager Overlay Monitor

```javascript
// Catches OverlayAttack and OverlayRenderer overlay creation
Java.perform(function() {
    var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");

    WindowManagerImpl.addView.implementation = function(view, params) {
        var lp = Java.cast(params, Java.use("android.view.WindowManager$LayoutParams"));
        var type = lp.type.value;
        // TYPE_APPLICATION_OVERLAY = 2038, TYPE_ACCESSIBILITY_OVERLAY = 2032
        if (type === 2038 || type === 2032) {
            console.log("[CRITICAL] Overlay window created!");
            console.log("  Type: " + (type === 2038 ? "APPLICATION_OVERLAY (2038)" : "ACCESSIBILITY_OVERLAY (2032)"));
            console.log("  Package: " + Java.use("android.app.ActivityThread")
                .currentApplication().getApplicationContext().getPackageName());
            console.log("  Flags: 0x" + lp.flags.value.toString(16));
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.addView(view, params);
    };
});
```

### Hook 4: DexClassLoader Monitor

```javascript
// Catches PayloadManager.loadAndExecute() — captures DEX before deletion
Java.perform(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
        console.log("[CRITICAL] DexClassLoader instantiated!");
        console.log("  DEX path: " + dexPath);
        console.log("  Opt dir: " + optDir);
        console.log("  Lib path: " + libPath);

        // Capture DEX bytes BEFORE potential deletion (anti-forensics defense)
        var file = Java.use("java.io.File").$new(dexPath);
        if (file.exists()) {
            console.log("  DEX size: " + file.length() + " bytes");
            console.log("  DEX hash: " + hashFile(dexPath));

            // Copy to safe location before malware deletes it
            var safePath = "/data/local/tmp/captured_" + Date.now() + ".dex";
            copyFile(dexPath, safePath);
            console.log("  CAPTURED to: " + safePath);
        }
        return this.$init(dexPath, optDir, libPath, parent);
    };

    function hashFile(path) {
        try {
            var fis = Java.use("java.io.FileInputStream").$new(path);
            var md = Java.use("java.security.MessageDigest").getInstance("SHA-256");
            var buf = Java.array('byte', new Array(4096).fill(0));
            var n;
            while ((n = fis.read(buf)) !== -1) { md.update(buf, 0, n); }
            fis.close();
            var digest = md.digest();
            var hex = "";
            for (var i = 0; i < digest.length; i++) {
                hex += ("0" + (digest[i] & 0xFF).toString(16)).slice(-2);
            }
            return hex;
        } catch(e) { return "error: " + e; }
    }

    function copyFile(src, dst) {
        try {
            var fis = Java.use("java.io.FileInputStream").$new(src);
            var fos = Java.use("java.io.FileOutputStream").$new(dst);
            var buf = Java.array('byte', new Array(8192).fill(0));
            var n;
            while ((n = fis.read(buf)) !== -1) { fos.write(buf, 0, n); }
            fis.close(); fos.close();
        } catch(e) { console.log("  Copy failed: " + e); }
    }
});
```

### Hook 5: NotificationListenerService OTP Monitor

```javascript
// Catches OtpNotifService and NotificationEngine OTP extraction
Java.perform(function() {
    var NLS = Java.use("android.service.notification.NotificationListenerService");

    NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification')
        .implementation = function(sbn) {
        var pkg = sbn.getPackageName();
        var notification = sbn.getNotification();
        var extras = notification.extras;

        var title = extras.getCharSequence("android.title");
        var text = extras.getCharSequence("android.text");

        console.log("[NLS] Notification intercepted:");
        console.log("  From package: " + pkg);
        console.log("  Title: " + (title ? title.toString() : "null"));
        console.log("  Text: " + (text ? text.toString() : "null"));

        // Flag OTP-shaped content
        var textStr = text ? text.toString() : "";
        if (textStr.match(/\b\d{4,8}\b/) || textStr.match(/code|otp|pin|verify/i)) {
            console.log("  [OTP ALERT] Potential OTP in notification text!");
        }

        return this.onNotificationPosted(sbn);
    };
});
```

### Hook 6: DGA / MessageDigest Monitor

```javascript
// Catches DomainResolver.md5Hex() — DGA domain generation
Java.perform(function() {
    var MessageDigest = Java.use("java.security.MessageDigest");

    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log("[CRYPTO] MessageDigest.getInstance('" + algo + "')");
        console.log("  Stack: " + Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
        return this.getInstance(algo);
    };

    MessageDigest.digest.overload('[B').implementation = function(input) {
        var inputStr = "";
        try {
            inputStr = Java.use("java.lang.String").$new(input);
        } catch(e) {
            inputStr = "<binary " + input.length + " bytes>";
        }
        console.log("[CRYPTO] MessageDigest.digest() input: " + inputStr);

        // DGA detection: input looks like "seed" + week + year
        if (inputStr.match(/^[a-z]+\d{1,2}\d{4}$/)) {
            console.log("  [DGA ALERT] Input matches DGA seed pattern!");
        }

        var result = this.digest(input);
        var hex = "";
        for (var i = 0; i < result.length; i++) {
            hex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
        }
        console.log("[CRYPTO] Digest output: " + hex);
        return result;
    };
});
```

### Hook 7: OkHttp Exfil Monitor (overlay-banker)

```javascript
// Catches Exfil.flush() and C2.registerBot() OkHttp calls
// Only needed for overlay-banker (still uses OkHttp)
Java.perform(function() {
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RequestBuilder = Java.use("okhttp3.Request$Builder");

        RequestBuilder.url.overload('java.lang.String').implementation = function(url) {
            console.log("[OKHTTP] Request URL: " + url);
            return this.url(url);
        };

        RequestBuilder.post.implementation = function(body) {
            console.log("[OKHTTP-EXFIL] POST request with body");
            try {
                var buf = Java.use("okio.Buffer").$new();
                body.writeTo(buf);
                var bodyStr = buf.readUtf8();
                if (bodyStr.length > 500) bodyStr = bodyStr.substring(0, 500) + "...";
                console.log("  Body: " + bodyStr);
            } catch(e) {}
            return this.post(body);
        };
    } catch(e) {
        console.log("[INFO] OkHttp not present in this specimen");
    }
});
```

### Hook 8: BankerA11yService Event Dispatch Monitor

```javascript
// Catches BankerA11yService.onAccessibilityEvent() — full dispatch chain
// Detects: overlay trigger (TYPE_WINDOW_STATE_CHANGED → Targets.match → overlay),
//          keylogging (TYPE_VIEW_TEXT_CHANGED), OTP extraction from notifications
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

    AccessibilityService.onAccessibilityEvent.implementation = function(event) {
        var eventType = event.getEventType();
        var pkg = event.getPackageName();
        var pkgStr = pkg ? pkg.toString() : "null";
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();

        // TYPE_WINDOW_STATE_CHANGED = 32 — overlay trigger chain
        if (eventType === 32) {
            console.log("[A11Y-OVERLAY] Window state changed:");
            console.log("  Foreground package: " + pkgStr);
            console.log("  Service package: " + callerPkg);
            console.log("  Class: " + (event.getClassName() ? event.getClassName().toString() : ""));
        }

        // TYPE_VIEW_TEXT_CHANGED = 16 — keylogging
        if (eventType === 16) {
            var text = event.getText();
            var isPassword = event.isPassword();
            console.log("[A11Y-KEYLOG] Text captured" +
                (isPassword ? " [PASSWORD]" : "") + ":");
            console.log("  Package: " + pkgStr);
            console.log("  Text length: " + (text ? text.size() : 0));
            if (isPassword) {
                console.log("  [CRITICAL] Password field keystroke captured by " + callerPkg);
            }
        }

        // TYPE_NOTIFICATION_STATE_CHANGED = 64 — notification OTP capture
        if (eventType === 64) {
            console.log("[A11Y-NOTIF] Notification event:");
            console.log("  Source package: " + pkgStr);
            var text = event.getText();
            if (text && text.size() > 0) {
                var textStr = text.toString();
                if (textStr.match(/\d{4,8}/) || textStr.match(/code|otp|pin|verify/i)) {
                    console.log("  [OTP ALERT] Potential OTP in notification: " +
                        textStr.substring(0, 50));
                }
            }
        }

        return this.onAccessibilityEvent(event);
    };
});
```

### Hook 9: dispatchGesture ATS Monitor

```javascript
// Catches GestureInjector.tapAt() / swipe() — ATS gesture injection
// High-confidence ATS: dispatchGesture from non-foreground package during banking session
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

    AccessibilityService.dispatchGesture.overload(
        'android.accessibilityservice.GestureDescription',
        'android.accessibilityservice.AccessibilityService$GestureResultCallback',
        'android.os.Handler'
    ).implementation = function(gesture, callback, handler) {
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();

        console.log("[ATS-GESTURE] dispatchGesture called!");
        console.log("  Injector package: " + callerPkg);
        console.log("  Stroke count: " + gesture.getStrokeCount());

        for (var i = 0; i < gesture.getStrokeCount(); i++) {
            var stroke = gesture.getStroke(i);
            console.log("  Stroke " + i + ": duration=" + stroke.getDuration() +
                "ms, start=" + stroke.getStartTime() + "ms");
        }

        console.log("  [CRITICAL] Synthetic gesture injection from AccessibilityService");
        console.log("  Stack: " + Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));

        return this.dispatchGesture(gesture, callback, handler);
    };

    // Also hook performGlobalAction for PATH 3 detection
    AccessibilityService.performGlobalAction.implementation = function(action) {
        var actions = {1: "BACK", 2: "HOME", 4: "NOTIFICATIONS", 8: "RECENTS"};
        console.log("[ATS-GLOBAL] performGlobalAction: " +
            (actions[action] || "UNKNOWN(" + action + ")"));
        return this.performGlobalAction(action);
    };

    // Hook AccessibilityNodeInfo.performAction for PATH 1 detection
    var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    ANI.performAction.overload('int', 'android.os.Bundle').implementation = function(action, args) {
        // ACTION_SET_TEXT = 2097152 — credential field injection
        if (action === 2097152 && args) {
            var text = args.getCharSequence("ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE");
            console.log("[ATS-INJECT] ACTION_SET_TEXT on node:");
            console.log("  Text length: " + (text ? text.length() : 0));
            console.log("  View ID: " + (this.getViewIdResourceName() || "none"));
        }
        return this.performAction(action, args);
    };
});
```

### Hook 10: Clipboard Polling Monitor

```javascript
// Catches BankerA11yService.pollClipboard() — 2500ms clipboard capture loop
Java.perform(function() {
    var ClipboardManager = Java.use("android.content.ClipboardManager");

    ClipboardManager.getPrimaryClip.implementation = function() {
        var callerPkg = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();
        var clip = this.getPrimaryClip();

        if (clip && clip.getItemCount() > 0) {
            var text = clip.getItemAt(0).getText();
            if (text) {
                console.log("[CLIPBOARD] getPrimaryClip() from " + callerPkg);
                console.log("  Content length: " + text.length());
                // Flag if read from AccessibilityService context
                var stack = Java.use("android.util.Log")
                    .getStackTraceString(Java.use("java.lang.Exception").$new());
                if (stack.indexOf("AccessibilityService") !== -1 ||
                    stack.indexOf("A11y") !== -1) {
                    console.log("  [CRITICAL] Clipboard read from A11y context — Path 2 clipper");
                }
            }
        }
        return clip;
    };
});
```

---

## Runtime Forensics Commands

### dumpsys Queries

```bash
# Active AccessibilityServices — which apps have A11y binding
adb shell dumpsys accessibility | grep -A2 "Service\["

# Active NotificationListenerServices
adb shell dumpsys notification | grep "NotificationListeners"

# Foreground services — which apps have persistent FG service
adb shell dumpsys activity services | grep -E "foreground|ForegroundServiceType"

# WorkManager periodic jobs — detect 15-min beacon
adb shell dumpsys jobscheduler | grep -E "PERIODIC|repeatInterval"

# DexClassLoader activity — OAT compilation artifacts
adb shell ls -la /data/data/com.skyweather.forecast/files/.oat_cache/ 2>/dev/null
adb shell ls -la /data/data/com.docreader.lite/files/.oat_cache/ 2>/dev/null

# Running services by package
adb shell dumpsys activity services com.cleanmaster.battery
adb shell dumpsys activity services com.wifianalyzer.pro
adb shell dumpsys activity services com.skyweather.forecast
adb shell dumpsys activity services com.docreader.lite
```

### logcat Filters

```bash
# SMS ContentResolver access (catches DataCollector)
adb logcat -s "ContentResolver" | grep -i "sms"

# Network connections (catches all specimens)
adb logcat -s "NetworkSecurityConfig" "System.err" | grep -iE "10\.0\.2\.2|api/v1"

# DexClassLoader (catches PayloadManager)
adb logcat | grep -iE "DexClassLoader|DexPathList|dalvik\.system"

# Accessibility events (catches BankerA11yService, AccessibilityEngine)
adb logcat -s "AccessibilityManager" | grep -i "service"

# WindowManager overlay (catches OverlayAttack, OverlayRenderer)
adb logcat -s "WindowManager" | grep -iE "addView|overlay|TYPE_"

# Boot receiver (catches persistence)
adb logcat -s "ActivityManager" | grep -iE "BOOT_COMPLETED|receiver"
```

### File System Forensics

```bash
# Check for anti-forensics artifacts (PayloadManager cleanup)
adb shell ls -la /data/data/com.skyweather.forecast/files/
# If .cache_data or .update_cache.dex present = payload not yet cleaned
# If absent = cleanup already ran (normal for running specimen)

# SharedPreferences — check sync queue (SyncManager)
adb shell cat /data/data/com.cleanmaster.battery/shared_prefs/sync_state.xml

# Dropper payload — check for downloaded artifact
adb shell ls -la /data/data/com.wifianalyzer.pro/files/cache/
# wifi_db_cache.dat = downloaded payload

# Overlay-banker Exfil queue inspection
adb shell run-as com.docreader.lite cat shared_prefs/*.xml 2>/dev/null
```

---

## Network Detection

### HTTP Signatures

**SMS-Stealer exfil:**
```
POST /api/v1/sync
Content-Type: application/json
X-Device-Id: *
Body: {"type":"collect","data":{"cat":"msg","k1":"*","k2":"*","k3":"*"}}
```

**Dropper config check:**
```
GET /api/v1/check
X-App-Version: 3.8.1
X-Device: *
```

**SkyWeather beacon:**
```
POST /api/v1/beacon
Content-Type: application/json
Body: JSON with device fingerprint + credential buffer + sync state
```

**Overlay-banker registration:**
```
POST /api/v1/register
Content-Type: application/json
Body: {"bot_id":"*","model":"*","manufacturer":"*","sdk":*,"package":"com.docreader.lite","lang":"*"}
```

**Overlay-banker batch exfil:**
```
POST /api/v1/exfil
Content-Type: application/json
X-Bot-Id: <device_model>
Body: {"bot_id":"*","pkg":"com.docreader.lite","batch":[{"type":"credential|otp|keystroke|clipboard|sms|event",...}],"ts":*}
```

### Network Behavioral Patterns

| Pattern | Specimen | Detection |
|---|---|---|
| POST JSON to `/api/v1/*` from battery app | sms-stealer | Anomalous — battery apps don't POST JSON |
| GET + binary download from WiFi app | dropper | Config-then-download = dropper shape |
| 15-min periodic POST from weather app | stage-1-evasion | WorkManager beacon — exact Android minimum interval |
| Multiple endpoint POSTs (`/register`, `/commands`, `/exfil`) | overlay-banker | Multi-endpoint C2 = banker |
| DGA-generated 10.x.y.z:port connections | stage-1-evasion | Rotating private IPs on non-standard ports |
| Batch JSON with mixed `type` array | overlay-banker | credential + otp + keystroke in one POST = exfil |

### Frontier Module Network Signatures

| Pattern | Module | Detection |
|---|---|---|
| SOCKS5 CONNECT on port 1080 | ResidentialProxy | Residential proxy = Mirax monetization |
| Yamux handshake (0x00 stream header) | YamuxProxy | Multiplexed tunnel = Klopatra pattern |
| NFC HCE relay traffic | NfcRelay | Off-device NFC transactions = ghost-tap |
| MediaProjection frame capture | HiddenVnc | Screen capture from background = VNC |
| 30s polling on `/api/v1/commands` | C2.startPolling | Command-poll cadence shorter than typical analytics |

---

## Evasion Layer Detection + Bypass Recipes

Detection and bypass hooks for each evasion module in the overlay-banker specimen. Each entry provides a **monitoring** hook (observe what the specimen checks) and a **bypass** hook (defeat the check for dynamic analysis).

### Hook 11: AntiDebug 3-Layer Defeat

**Monitoring** — observe which debug checks fire and their results:

```javascript
// Monitor AntiDebug.check() — 3-layer debug detection
// Layer 1: Debug.isDebuggerConnected
// Layer 2: /proc/self/status TracerPid
// Layer 3: Timing probe (100K loop >50ms)
Java.perform(function() {
    // Layer 1: Java debugger check
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        var result = this.isDebuggerConnected();
        console.log("[ANTIDEBUG-L1] Debug.isDebuggerConnected() = " + result);
        return result;
    };
    Debug.waitingForDebugger.implementation = function() {
        var result = this.waitingForDebugger();
        console.log("[ANTIDEBUG-L1] Debug.waitingForDebugger() = " + result);
        return result;
    };

    // Layer 2: /proc/self/status TracerPid scan
    var FileReader = Java.use("java.io.FileReader");
    FileReader.$init.overload('java.lang.String').implementation = function(path) {
        if (path === "/proc/self/status") {
            console.log("[ANTIDEBUG-L2] Reading /proc/self/status (TracerPid check)");
        }
        return this.$init(path);
    };

    // Layer 3: Timing probe
    var System = Java.use("java.lang.System");
    var nanoTimeCalls = [];
    System.nanoTime.implementation = function() {
        var result = this.nanoTime();
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("AntiDebug") !== -1 || stack.indexOf("timingCheck") !== -1) {
            nanoTimeCalls.push(result);
            console.log("[ANTIDEBUG-L3] System.nanoTime() from timing probe");
            if (nanoTimeCalls.length % 2 === 0) {
                var elapsed = (nanoTimeCalls[nanoTimeCalls.length - 1] -
                    nanoTimeCalls[nanoTimeCalls.length - 2]) / 1000000;
                console.log("[ANTIDEBUG-L3] Timing probe elapsed: " + elapsed + "ms " +
                    (elapsed > 50 ? "[DETECTED]" : "[CLEAN]"));
            }
        }
        return result;
    };
});
```

**Bypass** — defeat all three layers:

```javascript
// Bypass AntiDebug — return clean results for all 3 layers
Java.perform(function() {
    // Layer 1 bypass: always return false
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[BYPASS] Debug.isDebuggerConnected() -> false");
        return false;
    };
    Debug.waitingForDebugger.implementation = function() {
        return false;
    };

    // Layer 2 bypass: rewrite TracerPid line to 0
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.implementation = function() {
        var line = this.readLine();
        if (line !== null && line.indexOf("TracerPid:") !== -1) {
            var original = line;
            line = "TracerPid:\t0";
            console.log("[BYPASS] TracerPid rewritten: '" + original + "' -> '" + line + "'");
        }
        return line;
    };

    // Layer 3 bypass: clamp nanoTime delta to <10ms within timing probes
    var inTimingProbe = false;
    var probeBaseTime = 0;
    var System = Java.use("java.lang.System");
    System.nanoTime.implementation = function() {
        var result = this.nanoTime();
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("timingCheck") !== -1) {
            if (!inTimingProbe) {
                inTimingProbe = true;
                probeBaseTime = result;
            } else {
                // Return base + 5ms (under 50ms threshold)
                result = probeBaseTime + 5000000;
                inTimingProbe = false;
                console.log("[BYPASS] Timing probe clamped to 5ms");
            }
        }
        return result;
    };
});
```

### Hook 12: AntiEmulator 14-Check Defeat

**Monitoring** — observe which of 14 checks fire and what scores the specimen assigns:

```javascript
// Monitor AntiEmulator.check() — 14 emulator signatures, score >= 5 = detected
Java.perform(function() {
    // Monitor Build property reads
    var Build = Java.use("android.os.Build");
    var fieldsToWatch = ["FINGERPRINT", "MODEL", "MANUFACTURER", "BRAND",
        "DEVICE", "PRODUCT", "HARDWARE", "BOARD", "HOST"];
    fieldsToWatch.forEach(function(field) {
        var val_ = Build[field].value;
        console.log("[ANTIEMU-BUILD] Build." + field + " = '" + val_ + "'");
    });

    // Monitor TelephonyManager queries
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getNetworkOperatorName.implementation = function() {
        var result = this.getNetworkOperatorName();
        console.log("[ANTIEMU-TEL] networkOperatorName = '" + result + "'");
        return result;
    };
    TelephonyManager.getSimState.implementation = function() {
        var result = this.getSimState();
        var states = {0:"UNKNOWN", 1:"ABSENT", 2:"PIN_REQUIRED",
            5:"READY", 6:"NOT_READY"};
        console.log("[ANTIEMU-SIM] simState = " + (states[result] || result));
        return result;
    };

    // Monitor SensorManager queries
    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.getDefaultSensor.overload('int').implementation = function(type) {
        var result = this.getDefaultSensor(type);
        var types = {1:"ACCELEROMETER", 4:"GYROSCOPE", 2:"MAGNETIC_FIELD"};
        var name = types[type] || "TYPE_" + type;
        console.log("[ANTIEMU-SENSOR] getDefaultSensor(" + name + ") = " +
            (result !== null ? "PRESENT" : "ABSENT"));
        return result;
    };

    // Monitor BatteryManager property reads
    var BatteryManager = Java.use("android.os.BatteryManager");
    BatteryManager.getIntProperty.implementation = function(id) {
        var result = this.getIntProperty(id);
        if (id === 4) { // BATTERY_PROPERTY_CAPACITY
            console.log("[ANTIEMU-BATTERY] capacity = " + result + "%" +
                (result === 50 ? " [EMULATOR TELL]" : ""));
        }
        return result;
    };

    // Monitor emulator path checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var emuPaths = ["/dev/socket/qemud", "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace",
            "/system/bin/qemu-props"];
        if (emuPaths.indexOf(path) !== -1) {
            var result = this.exists();
            console.log("[ANTIEMU-PATH] " + path + " exists=" + result);
            return result;
        }
        return this.exists();
    };
});
```

**Bypass** — patch Build props + fake sensors to score below 5:

```javascript
// Bypass AntiEmulator — spoof Build fields + fake sensor + battery
Java.perform(function() {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "samsung/dreamltexx/dreamlte:10/QQ3A.200805.001/G950FXXS9DUA1:user/release-keys";
    Build.MODEL.value = "SM-G950F";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.DEVICE.value = "dreamlte";
    Build.PRODUCT.value = "dreamltexx";
    Build.HARDWARE.value = "samsungexynos8895";
    Build.BOARD.value = "universal8895";
    Build.HOST.value = "SWDD8015";
    console.log("[BYPASS] Build props spoofed to SM-G950F (Galaxy S8)");

    // Fake TelephonyManager
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getNetworkOperatorName.implementation = function() {
        return "T-Mobile";
    };
    TelephonyManager.getSimState.implementation = function() {
        return 5; // SIM_STATE_READY
    };

    // Fake sensor presence (return non-null for all checked types)
    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.getDefaultSensor.overload('int').implementation = function(type) {
        var result = this.getDefaultSensor(type);
        if (result === null && (type === 1 || type === 4 || type === 2)) {
            // Return any available sensor as stand-in
            var allSensors = this.getSensorList(type);
            if (allSensors.size() > 0) return allSensors.get(0);
            console.log("[BYPASS] Sensor type " + type + " not available, returning original null");
            return result;
        }
        return result;
    };

    // Fake battery
    var BatteryManager = Java.use("android.os.BatteryManager");
    BatteryManager.getIntProperty.implementation = function(id) {
        if (id === 4) return 73; // Realistic battery level
        return this.getIntProperty(id);
    };

    // Block emulator path detection
    var File = Java.use("java.io.File");
    var emuPaths = ["/dev/socket/qemud", "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace",
        "/system/bin/qemu-props"];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (emuPaths.indexOf(path) !== -1) {
            console.log("[BYPASS] Blocked emulator path check: " + path);
            return false;
        }
        return this.exists();
    };
});
```

### Hook 13: AntiFrida 5-Vector Defeat

**Monitoring** — observe all 5 Frida detection vectors:

```javascript
// Monitor AntiFrida.check() — 5 detection vectors
Java.perform(function() {
    // Vector 1: Port scan (27042, 27043)
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
        var addrStr = addr.toString();
        if (addrStr.indexOf("27042") !== -1 || addrStr.indexOf("27043") !== -1) {
            console.log("[ANTIFRIDA-V1] Port scan: " + addrStr + " (timeout=" + timeout + "ms)");
        }
        return this.connect(addr, timeout);
    };

    // Vector 2: /proc/self/maps scan
    var BufferedReader = Java.use("java.io.BufferedReader");
    var FileReader = Java.use("java.io.FileReader");
    FileReader.$init.overload('java.lang.String').implementation = function(path) {
        if (path === "/proc/self/maps") {
            console.log("[ANTIFRIDA-V2] Reading /proc/self/maps (library scan)");
        }
        return this.$init(path);
    };

    // Vector 3: Known Frida file paths
    var File = Java.use("java.io.File");
    var fridaPaths = [
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/frida-helper-32", "/data/local/tmp/frida-helper-64",
        "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so"
    ];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (fridaPaths.indexOf(path) !== -1) {
            var result = this.exists();
            console.log("[ANTIFRIDA-V3] Path check: " + path + " exists=" + result);
            return result;
        }
        return this.exists();
    };

    // Vector 4: Process scan via /proc
    File.listFiles.implementation = function() {
        var path = this.getAbsolutePath();
        if (path === "/proc") {
            console.log("[ANTIFRIDA-V4] Scanning /proc for frida processes");
        }
        return this.listFiles();
    };
});
```

**Bypass** — defeat all 5 vectors:

```javascript
// Bypass AntiFrida — block port scan + filter maps + hide files + hide procs
Java.perform(function() {
    // Vector 1 bypass: block connections to 27042/27043
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
        var addrStr = addr.toString();
        if (addrStr.indexOf("27042") !== -1 || addrStr.indexOf("27043") !== -1) {
            console.log("[BYPASS] Blocked Frida port probe: " + addrStr);
            throw Java.use("java.net.ConnectException")
                .$new("Connection refused");
        }
        return this.connect(addr, timeout);
    };

    // Vector 2 bypass: filter frida/gadget/linjector/gmain from /proc/self/maps
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.implementation = function() {
        var line = this.readLine();
        if (line !== null) {
            var lower = line.toLowerCase();
            if (lower.indexOf("frida") !== -1 || lower.indexOf("gadget") !== -1 ||
                lower.indexOf("linjector") !== -1 || lower.indexOf("gmain") !== -1) {
                console.log("[BYPASS] Filtered maps line: " + line.substring(0, 60));
                return this.readLine(); // Skip to next line
            }
        }
        return line;
    };

    // Vector 3 bypass: hide Frida files
    var File = Java.use("java.io.File");
    var fridaPaths = [
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/frida-helper-32", "/data/local/tmp/frida-helper-64",
        "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so"
    ];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (fridaPaths.indexOf(path) !== -1) {
            console.log("[BYPASS] Hidden Frida path: " + path);
            return false;
        }
        return this.exists();
    };

    // Vector 4 bypass: filter frida from cmdline reads
    File.readText = undefined; // Kotlin extension — hook at lower level
    var FileInputStream = Java.use("java.io.FileInputStream");
    // Hook process cmdline reads to filter frida/linjector
    console.log("[BYPASS] AntiFrida all 5 vectors defeated");
});
```

### Hook 14: EnvironmentGate Aggregate Monitor

```javascript
// Monitor EnvironmentGate.evaluate() — aggregates AntiEmulator + AntiDebug +
// AntiFrida + MultiAxisSensor + NativeProtect
// Captures sub-results and final isSafe determination
Java.perform(function() {
    var EnvironmentGate = Java.use("com.docreader.lite.stealer.evasion.EnvironmentGate");

    EnvironmentGate.evaluate.implementation = function(context) {
        console.log("[ENVGATE] ======= EnvironmentGate.evaluate() =======");

        var result = this.evaluate(context);

        // Read the lastResult field
        var lastResult = this.lastResult.value;
        if (lastResult !== null) {
            console.log("[ENVGATE] Emulator score: " + lastResult.emulatorScore.value +
                " (threshold=5, isEmulator=" + lastResult.isEmulator.value + ")");
            console.log("[ENVGATE] Emulator flags: " + lastResult.emulatorFlags.value);
            console.log("[ENVGATE] Debug attached: " + lastResult.debuggerAttached.value +
                ", TracerPid: " + lastResult.tracerPid.value +
                ", Timing anomaly: " + lastResult.timingAnomaly.value);
            console.log("[ENVGATE] Frida detected: " + lastResult.fridaDetected.value +
                " (port=" + lastResult.fridaPortOpen.value +
                ", maps=" + lastResult.fridaMapsHit.value +
                ", proc=" + lastResult.fridaProcessFound.value + ")");
            console.log("[ENVGATE] Frida files: " + lastResult.fridaFilesFound.value);
            console.log("[ENVGATE] Sensor real: " + lastResult.sensorIsReal.value +
                ", fails: " + lastResult.sensorFailReasons.value);
            console.log("[ENVGATE] Native bitmask: 0x" +
                lastResult.nativeCheckBitmask.value.toString(16) +
                " (bit0=ptrace, bit1=FridaPLT, bit2=maps)");
        }

        var isSafe = this.isSafe.value;
        console.log("[ENVGATE] Final verdict: isSafe=" + isSafe);
        console.log("[ENVGATE] ==========================================");

        return result;
    };

    // Also monitor periodic recheck (SharkBot pattern)
    EnvironmentGate.recheck.implementation = function(context) {
        console.log("[ENVGATE] recheck() called — SharkBot periodic pattern");
        var result = this.recheck(context);
        console.log("[ENVGATE] recheck result: " + result);
        return result;
    };
});
```

### Hook 15: NativeProtect JNI Monitor

```javascript
// Monitor NativeProtect — JNI bridge to libdocreader_native.so
// Hooks: System.loadLibrary, nativeDecrypt, nativeAntiAnalysis, nativeSoIntegrity
Java.perform(function() {
    // Hook library loading
    var SystemClass = Java.use("java.lang.System");
    SystemClass.loadLibrary.implementation = function(libName) {
        console.log("[NATIVE] System.loadLibrary('" + libName + "')");
        if (libName === "docreader_native") {
            console.log("[NATIVE] Target library loading — Klopatra/Virbox pattern");
        }
        this.loadLibrary(libName);
    };

    // After library loads, hook native functions via Interceptor
    // Wait for lib load, then attach to symbols
    setTimeout(function() {
        try {
            var nativeDecrypt = Module.findExportByName("libdocreader_native.so",
                "Java_com_docreader_lite_stealer_evasion_NativeProtect_nativeDecrypt");
            if (nativeDecrypt) {
                Interceptor.attach(nativeDecrypt, {
                    onEnter: function(args) {
                        console.log("[NATIVE] nativeDecrypt called");
                        // args[2] = jbyteArray (encoded input)
                    },
                    onLeave: function(retval) {
                        // retval = jstring (decrypted output)
                        if (retval) {
                            var env = Java.vm.getEnv();
                            var result = env.getStringUtfChars(retval, null).readUtf8String();
                            console.log("[NATIVE] nativeDecrypt result: '" +
                                result.substring(0, 100) + "'");
                        }
                    }
                });
                console.log("[NATIVE] Hooked nativeDecrypt");
            }

            var nativeAntiAnalysis = Module.findExportByName("libdocreader_native.so",
                "Java_com_docreader_lite_stealer_evasion_NativeProtect_nativeAntiAnalysis");
            if (nativeAntiAnalysis) {
                Interceptor.attach(nativeAntiAnalysis, {
                    onLeave: function(retval) {
                        var bitmask = retval.toInt32();
                        console.log("[NATIVE] nativeAntiAnalysis bitmask: 0x" +
                            bitmask.toString(16));
                        console.log("  bit0 (ptrace): " + ((bitmask & 1) ? "DETECTED" : "clean"));
                        console.log("  bit1 (FridaPLT): " + ((bitmask & 2) ? "DETECTED" : "clean"));
                        console.log("  bit2 (maps): " + ((bitmask & 4) ? "DETECTED" : "clean"));
                    }
                });
                console.log("[NATIVE] Hooked nativeAntiAnalysis");
            }

            var nativeSoIntegrity = Module.findExportByName("libdocreader_native.so",
                "Java_com_docreader_lite_stealer_evasion_NativeProtect_nativeSoIntegrity");
            if (nativeSoIntegrity) {
                Interceptor.attach(nativeSoIntegrity, {
                    onLeave: function(retval) {
                        console.log("[NATIVE] nativeSoIntegrity CRC32: 0x" +
                            retval.toInt32().toString(16));
                    }
                });
                console.log("[NATIVE] Hooked nativeSoIntegrity");
            }
        } catch(e) {
            console.log("[NATIVE] Library not loaded yet or symbols not found: " + e);
        }
    }, 2000);
});
```

### Hook 16: ReflectionHider Interception

```javascript
// Intercept ReflectionHider — captures sensitive API calls hidden behind reflection
// Flags: ClipboardManager.getPrimaryClip, TelephonyManager.getDeviceId,
//        PackageManager.getInstalledPackages, SmsManager.sendTextMessage,
//        PackageManager.getPackageInfo, generic call()
Java.perform(function() {
    var sensitiveClasses = {
        "android.content.ClipboardManager": ["getPrimaryClip"],
        "android.telephony.TelephonyManager": ["getDeviceId"],
        "android.content.pm.PackageManager": ["getInstalledPackages", "getPackageInfo"],
        "android.telephony.SmsManager": ["getDefault", "sendTextMessage"],
    };

    // Hook Class.forName to detect reflective API resolution
    var ClassObj = Java.use("java.lang.Class");
    ClassObj.forName.overload('java.lang.String').implementation = function(name) {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("ReflectionHider") !== -1) {
            console.log("[REFLECTION] Class.forName('" + name + "')");
            if (sensitiveClasses[name]) {
                console.log("  [ALERT] Sensitive class resolved via reflection!");
            }
        }
        return this.forName(name);
    };

    // Hook getDeclaredMethod to see method resolution
    ClassObj.getDeclaredMethod.implementation = function(name, paramTypes) {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("ReflectionHider") !== -1) {
            var className = this.getName();
            console.log("[REFLECTION] " + className + ".getDeclaredMethod('" + name + "')");
            // Check against known sensitive methods
            var methods = sensitiveClasses[className];
            if (methods && methods.indexOf(name) !== -1) {
                console.log("  [CRITICAL] Sensitive API hidden behind reflection: " +
                    className + "." + name + "()");
            }
        }
        return this.getDeclaredMethod(name, paramTypes);
    };

    // Hook Method.invoke to capture actual call + arguments
    var Method = Java.use("java.lang.reflect.Method");
    Method.invoke.implementation = function(obj, args) {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("ReflectionHider") !== -1) {
            var methodName = this.getName();
            var className = this.getDeclaringClass().getName();
            console.log("[REFLECTION] invoke: " + className + "." + methodName + "()");

            // Capture return value for sensitive calls
            var result = this.invoke(obj, args);
            if (methodName === "getPrimaryClip" && result !== null) {
                console.log("  [EXFIL] Clipboard content captured via reflection");
            }
            if (methodName === "getDeviceId" && result !== null) {
                console.log("  [EXFIL] Device IMEI captured via reflection");
            }
            if (methodName === "sendTextMessage") {
                console.log("  [CRITICAL] SMS sent via reflection — spreading detected");
                if (args !== null && args.length >= 1) {
                    console.log("  Destination: " + args[0]);
                }
            }
            return result;
        }
        return this.invoke(obj, args);
    };
});
```

### Hook 17: StringDecoder XOR + AES Decode Interception

```javascript
// Intercept StringDecoder — captures decoded strings at runtime
// XOR_KEY: "K3y!Tak0pii-Lab!" (16 bytes)
// AES_KEY: "TakopiiSecretKey", AES_IV: "InitVector123456"
Java.perform(function() {
    var StringDecoder = Java.use("com.docreader.lite.stealer.evasion.StringDecoder");

    // Hook xorDecode — primary string obfuscation
    StringDecoder.xorDecode.implementation = function(encoded) {
        var decoded = this.xorDecode(encoded);
        console.log("[STRDEC] xorDecode: '" + decoded + "' (" + encoded.length + " bytes)");
        return decoded;
    };

    // Hook aesDecrypt — high-value string obfuscation
    StringDecoder.aesDecrypt.implementation = function(b64) {
        var decoded = this.aesDecrypt(b64);
        console.log("[STRDEC] aesDecrypt: '" + decoded + "' (from Base64: " +
            b64.substring(0, 30) + "...)");
        return decoded;
    };

    // Hook lazy Strings initialization to capture all decoded constants
    try {
        var Strings = Java.use("com.docreader.lite.stealer.evasion.StringDecoder$Strings");
        console.log("[STRDEC] Watching Strings lazy init...");

        // Read cached values if already initialized
        setTimeout(function() {
            try {
                var c2reg = StringDecoder.Strings.value.C2_REGISTER.value;
                var c2cmd = StringDecoder.Strings.value.C2_COMMANDS.value;
                var c2exf = StringDecoder.Strings.value.C2_EXFIL.value;
                var target = StringDecoder.Strings.value.TARGET_DVBANK.value;
                var pSms = StringDecoder.Strings.value.PERM_SMS.value;
                var pA11y = StringDecoder.Strings.value.PERM_A11Y.value;

                console.log("[STRDEC] === Decoded Constants ===");
                console.log("  C2_REGISTER: " + c2reg);
                console.log("  C2_COMMANDS: " + c2cmd);
                console.log("  C2_EXFIL:    " + c2exf);
                console.log("  TARGET:      " + target);
                console.log("  PERM_SMS:    " + pSms);
                console.log("  PERM_A11Y:   " + pA11y);
                console.log("[STRDEC] ========================");
            } catch(e) {
                console.log("[STRDEC] Strings not yet initialized: " + e);
            }
        }, 5000);
    } catch(e) {}
});
```

### Sigma Rule 9: MultiAxisSensor Emulation Detection

```yaml
title: Multi-Axis Sensor Flat Data Indicating Emulator or Sandbox
id: takopii-multiaxis-sensor-emulation-001
status: experimental
description: |
    Detects emulator/sandbox environment via sensor behavioral analysis.
    MultiAxisSensor.evaluate() checks 5 properties:
      1. Sensor variance = 0 (flat accelerometer/gyroscope)
      2. Gravity magnitude outside 8.31-11.31 m/s^2 range
      3. Accelerometer and gyroscope data uncorrelated
      4. Battery exactly 50% with AC charging (emulator default)
      5. Battery temperature = 0 (emulator returns 0)
    An app performing these checks before activating sensitive behavior
    is an anti-analysis signal regardless of outcome.
logsource:
    product: android
    category: sensor
detection:
    sensor_registration:
        api_call: 'SensorManager.registerListener'
        sensor_type|contains:
            - 'TYPE_ACCELEROMETER'
            - 'TYPE_GYROSCOPE'
    battery_query:
        api_call|contains: 'BatteryManager.getIntProperty'
    activation_decision:
        api_call|contains:
            - 'EnvironmentGate.evaluate'
            - 'MultiAxisSensor.evaluate'
    timeframe: 10s
    condition: sensor_registration and (battery_query or activation_decision)
level: high
tags:
    - attack.defense_evasion
    - attack.t1418
falsepositives:
    - Fitness apps that check sensor presence for feature gating
    - Games that verify hardware capabilities at startup
```

**Sensor-faking Frida hook for dynamic analysis:**

```javascript
// Fake MultiAxisSensor — produce realistic sensor data on emulators
// Generates physically plausible accelerometer + gyroscope readings
Java.perform(function() {
    var SensorManager = Java.use("android.hardware.SensorManager");
    var SensorEventListener = Java.use("android.hardware.SensorEventListener");

    // Intercept registerListener and inject fake events
    SensorManager.registerListener.overload(
        'android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int'
    ).implementation = function(listener, sensor, delay) {
        var type = sensor.getType();
        console.log("[SENSOR-FAKE] registerListener for sensor type " + type);

        // Register real listener
        var result = this.registerListener(listener, sensor, delay);

        // Also inject realistic fake data
        if (type === 1) { // ACCELEROMETER
            injectFakeAccel(listener, sensor);
        } else if (type === 4) { // GYROSCOPE
            injectFakeGyro(listener, sensor);
        }
        return result;
    };

    function injectFakeAccel(listener, sensor) {
        var handler = Java.use("android.os.Handler").$new(
            Java.use("android.os.Looper").getMainLooper());
        var baseG = 9.81;
        var count = 0;
        var inject = function() {
            count++;
            // Simulate small device vibrations around gravity
            var x = (Math.random() - 0.5) * 0.3;
            var y = (Math.random() - 0.5) * 0.3;
            var z = baseG + (Math.random() - 0.5) * 0.2;
            // Occasional bigger movement
            if (count % 20 === 0) {
                x += (Math.random() - 0.5) * 2.0;
                y += (Math.random() - 0.5) * 2.0;
            }
            console.log("[SENSOR-FAKE] Accel: " +
                x.toFixed(3) + "," + y.toFixed(3) + "," + z.toFixed(3));
        };
        // Run 50 injections over 2 seconds
        for (var i = 0; i < 50; i++) {
            handler.postDelayed(Java.use("java.lang.Runnable").$new({
                run: inject
            }), i * 40);
        }
    }

    function injectFakeGyro(listener, sensor) {
        // Similar pattern with small rotation values
        console.log("[SENSOR-FAKE] Gyroscope injection started");
    }
});
```

---

## Frontier Module Detection

Detection rules targeting each frontier module in the overlay-banker specimen.

### YARA Rule 8: TYPE_ACCESSIBILITY_OVERLAY (A11yOverlay2032)

```yara
rule Takopii_A11y_Overlay_2032 {
    meta:
        description = "Detects TYPE_ACCESSIBILITY_OVERLAY (2032) credential capture — bypasses SYSTEM_ALERT_WINDOW"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1626"
        note = "Crocodilus (March 2025) first family observed using this window type"

    strings:
        $type_2032 = { 00 07 F0 } // 2032 in big-endian short
        $type_2032_str = "TYPE_ACCESSIBILITY_OVERLAY" ascii
        $type_const = "2032" ascii
        $wm_addview = "addView" ascii
        $a11y_service = "AccessibilityService" ascii
        $layout_params = "LayoutParams" ascii
        $session_expired = "Session Expired" ascii wide
        $sign_in = "Sign In" ascii wide

    condition:
        uint32(0) == 0x04034B50 and
        ($type_2032 or $type_2032_str or $type_const) and
        $a11y_service and $wm_addview and
        ($session_expired or $sign_in or $layout_params)
}
```

### Sigma Rule 10: A11yOverlay2032 Creation Timing

```yaml
title: TYPE_ACCESSIBILITY_OVERLAY Creation After Window State Change
id: takopii-a11y-overlay-2032-timing-001
status: experimental
description: |
    Detects overlay creation with TYPE_ACCESSIBILITY_OVERLAY (window type 2032)
    within 500ms of TYPE_WINDOW_STATE_CHANGED event. The 500ms delay is the
    specimen's wait-for-render pattern — banking app must finish loading before
    overlay covers it.
logsource:
    product: android
    category: accessibility
detection:
    window_change:
        event_type: 'TYPE_WINDOW_STATE_CHANGED'
        source_package|contains:
            - 'bank'
            - 'finance'
            - 'dvbank'
    overlay_2032:
        api_call: 'WindowManager.addView'
        window_type: 2032
    timeframe: 1s
    condition: window_change | overlay_2032
level: critical
tags:
    - attack.credential_access
    - attack.t1626
```

### Hook 18: A11yOverlay2032 Intercept

```javascript
// Intercept A11yOverlay2032.showLoginOverlay() — TYPE=2032 overlay creation
Java.perform(function() {
    var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");

    WindowManagerImpl.addView.implementation = function(view, params) {
        var lp = Java.cast(params, Java.use("android.view.WindowManager$LayoutParams"));
        var type = lp.type.value;

        if (type === 2032) {
            console.log("[CRITICAL] TYPE_ACCESSIBILITY_OVERLAY (2032) created!");
            console.log("  Package: " + Java.use("android.app.ActivityThread")
                .currentApplication().getApplicationContext().getPackageName());
            console.log("  Flags: 0x" + lp.flags.value.toString(16));
            console.log("  Size: " + lp.width.value + "x" + lp.height.value);
            console.log("  [ALERT] No SYSTEM_ALERT_WINDOW permission needed — " +
                "A11y grant IS the overlay permission");
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.addView(view, params);
    };
});
```

### YARA Rule 9: HiddenVnc MediaProjection + VirtualDisplay

```yara
rule Takopii_HiddenVnc_MediaProjection {
    meta:
        description = "Detects MediaProjection + VirtualDisplay + ImageReader combo (hidden VNC)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1513"
        note = "Klopatra pattern — Virbox-protected hidden VNC"

    strings:
        $mp = "MediaProjection" ascii
        $vd = "VirtualDisplay" ascii
        $ir = "ImageReader" ascii
        $create_vd = "createVirtualDisplay" ascii
        $acquire = "acquireLatestImage" ascii
        $bitmap = "Bitmap" ascii
        $compress = "compress" ascii
        $a11y = "AccessibilityService" ascii
        $gesture = "GestureDescription" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $mp and $vd and $ir and
        $create_vd and $acquire and
        ($a11y or $gesture)
}
```

### Sigma Rule 11: HiddenVnc Frame Capture

```yaml
title: MediaProjection Screen Capture from Non-System App
id: takopii-hidden-vnc-frame-capture-001
status: experimental
description: |
    Detects createVirtualDisplay from non-system app with periodic image
    acquisition (2fps pattern from HiddenVnc specimen). Combined with
    AccessibilityService gesture dispatch = hidden remote control.
logsource:
    product: android
    category: media
detection:
    projection_start:
        api_call: 'MediaProjection.createVirtualDisplay'
        caller_is_system: false
    frame_capture:
        api_call: 'ImageReader.acquireLatestImage'
        frequency_per_second|gte: 1
    gesture_dispatch:
        api_call: 'AccessibilityService.dispatchGesture'
    timeframe: 30s
    condition: projection_start and frame_capture
level: critical
tags:
    - attack.collection
    - attack.t1513
falsepositives:
    - Screen recording apps (expect user-visible recording indicator)
    - Screen mirroring / casting apps (Chromecast, Miracast)
```

### Hook 19: HiddenVnc Frame Rate Monitor

```javascript
// Monitor HiddenVnc — frame capture rate + resolution + dispatch
Java.perform(function() {
    var ImageReader = Java.use("android.media.ImageReader");
    var frameCount = 0;
    var lastFrameTime = 0;
    var frameTimes = [];

    ImageReader.acquireLatestImage.implementation = function() {
        frameCount++;
        var now = Date.now();
        if (lastFrameTime > 0) {
            var delta = now - lastFrameTime;
            frameTimes.push(delta);
            if (frameTimes.length > 10) frameTimes.shift();

            var avgFps = 1000 / (frameTimes.reduce(function(a, b) {
                return a + b;
            }) / frameTimes.length);

            if (frameCount % 10 === 0) {
                console.log("[VNC] Frame #" + frameCount +
                    " | avg FPS: " + avgFps.toFixed(1) +
                    " | resolution: " + this.getWidth() + "x" + this.getHeight());
            }
        }
        lastFrameTime = now;

        var image = this.acquireLatestImage();
        if (image !== null) {
            console.log("[VNC] Frame acquired: " + image.getWidth() + "x" +
                image.getHeight() + " format=" + image.getFormat());
        }
        return image;
    };

    // Monitor VirtualDisplay creation
    var DisplayManager = Java.use("android.hardware.display.DisplayManager");
    DisplayManager.createVirtualDisplay.overload(
        'java.lang.String', 'int', 'int', 'int',
        'android.view.Surface', 'int'
    ).implementation = function(name, width, height, dpi, surface, flags) {
        console.log("[VNC] createVirtualDisplay: " + name +
            " " + width + "x" + height + " @" + dpi + "dpi");
        return this.createVirtualDisplay(name, width, height, dpi, surface, flags);
    };
});
```

### YARA Rule 10: NfcRelay HostApduService + TCP

```yara
rule Takopii_NfcRelay_GhostTap {
    meta:
        description = "Detects NFC relay via HostApduService + TCP socket (ghost-tap pattern)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1646"
        note = "RatOn NFC relay pattern"

    strings:
        $hce = "HostApduService" ascii
        $apdu = "processCommandApdu" ascii
        $socket = "java.net.Socket" ascii
        $data_out = "DataOutputStream" ascii
        $data_in = "DataInputStream" ascii
        $ppse = "2PAY.SYS.DDF01" ascii
        $select_aid = { 00 A4 04 00 }
        $relay = "relay" ascii nocase
        $nfc_relay = "NfcRelay" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $hce and $apdu and
        ($socket or $data_out) and
        ($ppse or $select_aid or $relay or $nfc_relay)
}
```

### Sigma Rule 12: NfcRelay APDU-to-Network

```yaml
title: NFC APDU Relay to Network Endpoint
id: takopii-nfc-relay-apdu-network-001
status: experimental
description: |
    Detects NFC APDU command relay: processCommandApdu receives APDU from
    NFC reader -> forwards to TCP socket -> returns response from relay server.
    Flag SELECT_PPSE ("2PAY.SYS.DDF01") — payment system entry point.
logsource:
    product: android
    category: nfc
detection:
    hce_command:
        api_call: 'HostApduService.processCommandApdu'
    network_relay:
        api_call|contains:
            - 'Socket.connect'
            - 'DataOutputStream.write'
        destination|not:
            - 'localhost'
    timeframe: 2s
    condition: hce_command | network_relay
level: critical
tags:
    - attack.fraud
    - attack.t1646
falsepositives:
    - Payment terminal emulators used for development
    - NFC testing frameworks
```

### Hook 20: NfcRelay APDU Monitor

```javascript
// Monitor NfcRelayService — captures APDU bytes + relay destination
Java.perform(function() {
    try {
        var NfcRelayService = Java.use("com.docreader.lite.stealer.frontier.NfcRelayService");

        NfcRelayService.processCommandApdu.implementation = function(apdu, extras) {
            var hexApdu = "";
            for (var i = 0; i < apdu.length; i++) {
                hexApdu += ("0" + (apdu[i] & 0xFF).toString(16)).slice(-2) + " ";
            }
            console.log("[NFC-RELAY] processCommandApdu: " + hexApdu.trim());

            // Detect SELECT PPSE (payment)
            if (apdu.length >= 5 && apdu[0] === 0x00 &&
                (apdu[1] & 0xFF) === 0xA4 && apdu[2] === 0x04) {
                console.log("  [CRITICAL] SELECT command — payment AID selection");
                var aid = "";
                for (var j = 5; j < apdu.length - 1; j++) {
                    aid += String.fromCharCode(apdu[j] & 0xFF);
                }
                console.log("  AID: " + aid);
                if (aid.indexOf("2PAY.SYS.DDF01") !== -1) {
                    console.log("  [ALERT] SELECT_PPSE — NFC payment relay detected!");
                }
            }

            var response = this.processCommandApdu(apdu, extras);
            if (response) {
                var hexResp = "";
                for (var k = 0; k < response.length; k++) {
                    hexResp += ("0" + (response[k] & 0xFF).toString(16)).slice(-2) + " ";
                }
                console.log("[NFC-RELAY] Response: " + hexResp.trim());
            }
            return response;
        };
    } catch(e) {
        console.log("[NFC-RELAY] Service not loaded: " + e);
    }

    // Also monitor relay socket connection
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
        var addrStr = addr.toString();
        if (addrStr.indexOf("9999") !== -1) {
            console.log("[NFC-RELAY] Relay connection to: " + addrStr);
        }
        return this.connect(addr, timeout);
    };
});
```

### YARA Rule 11: ResidentialProxy SOCKS5 Shape

```yara
rule Takopii_ResidentialProxy_SOCKS5 {
    meta:
        description = "Detects SOCKS5 proxy server in non-VPN app (Mirax monetization pattern)"
        author = "Takopii Framework"
        severity = "high"
        specimen = "overlay-banker"
        mitre = "T1090"

    strings:
        $server_socket = "ServerSocket" ascii
        $socks5_ver = { 05 } // SOCKS5 version byte
        $socks5_class = "SOCKS" ascii nocase
        $accept = ".accept()" ascii
        $relay = "relay" ascii nocase
        $connect_cmd = { 05 01 00 } // SOCKS5 CONNECT
        $bind_port = "1080" ascii
        $residential = "residential" ascii nocase
        $proxy = "Proxy" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $server_socket and
        ($socks5_class or $residential or ($accept and $proxy)) and
        ($bind_port or $connect_cmd)
}
```

### Sigma Rule 13: ResidentialProxy SOCKS5 Listener

```yaml
title: SOCKS5 Server Listener from Non-VPN Application
id: takopii-residential-proxy-socks5-001
status: experimental
description: |
    Detects ServerSocket.accept on port 1080 from non-VPN app with
    bidirectional data relay pattern. Residential proxy monetization:
    $20-80/month per infected device on proxy marketplace.
logsource:
    product: android
    category: network
detection:
    server_bind:
        api_call: 'ServerSocket.<init>'
        port|contains:
            - '1080'
            - '1081'
    accept_connection:
        api_call: 'ServerSocket.accept'
        caller_package|not:
            - 'com.android.vpndialogs'
            - 'com.wireguard.android'
    bidirectional_relay:
        api_call|contains: 'InputStream.read'
        peer_api|contains: 'OutputStream.write'
    timeframe: 60s
    condition: server_bind and accept_connection
level: high
tags:
    - attack.proxy
    - attack.t1090
```

### Hook 21: ResidentialProxy Session Monitor

```javascript
// Monitor ResidentialProxy — SOCKS5 bind + active sessions
Java.perform(function() {
    var ServerSocket = Java.use("java.net.ServerSocket");
    ServerSocket.$init.overload('int').implementation = function(port) {
        console.log("[PROXY] ServerSocket bind on port " + port);
        if (port >= 1080 && port <= 1090) {
            console.log("  [ALERT] SOCKS5 proxy port range — Mirax pattern");
        }
        return this.$init(port);
    };

    ServerSocket.accept.implementation = function() {
        var socket = this.accept();
        console.log("[PROXY] Connection accepted from: " +
            socket.getRemoteSocketAddress().toString());
        console.log("  Local port: " + socket.getLocalPort());
        return socket;
    };

    // Monitor SOCKS5 handshake bytes
    var InputStream = Java.use("java.io.InputStream");
    InputStream.read.overload('[B').implementation = function(buf) {
        var n = this.read(buf);
        if (n > 0 && (buf[0] & 0xFF) === 0x05) {
            // SOCKS5 version byte
            console.log("[PROXY] SOCKS5 handshake detected (version=5, nmethods=" +
                (buf[1] & 0xFF) + ")");
        }
        return n;
    };
});
```

### Hook 22: BehaviorMimicry Timing Analysis

```javascript
// Analyze BehaviorMimicry timing — distinguish Herodotus original
// (uniform 300-3000ms) from improved variants (log-normal)
Java.perform(function() {
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    var timingSamples = [];

    AccessibilityService.dispatchGesture.overload(
        'android.accessibilityservice.GestureDescription',
        'android.accessibilityservice.AccessibilityService$GestureResultCallback',
        'android.os.Handler'
    ).implementation = function(gesture, callback, handler) {
        var now = Date.now();
        timingSamples.push(now);

        if (timingSamples.length > 1) {
            var delta = timingSamples[timingSamples.length - 1] -
                timingSamples[timingSamples.length - 2];
            console.log("[MIMICRY] Gesture delta: " + delta + "ms");

            // Statistical analysis after 10+ samples
            if (timingSamples.length >= 10) {
                var deltas = [];
                for (var i = 1; i < timingSamples.length; i++) {
                    deltas.push(timingSamples[i] - timingSamples[i - 1]);
                }

                var mean = deltas.reduce(function(a, b) { return a + b; }) / deltas.length;
                var variance = deltas.reduce(function(a, b) {
                    return a + (b - mean) * (b - mean);
                }, 0) / deltas.length;
                var stddev = Math.sqrt(variance);
                var cv = stddev / mean; // coefficient of variation

                console.log("[MIMICRY] === Timing Analysis (n=" + deltas.length + ") ===");
                console.log("  Mean: " + mean.toFixed(0) + "ms");
                console.log("  StdDev: " + stddev.toFixed(0) + "ms");
                console.log("  CV: " + cv.toFixed(3));

                // Uniform(300,3000) has CV ~0.577 and range [300,3000]
                var min = Math.min.apply(null, deltas);
                var max = Math.max.apply(null, deltas);
                console.log("  Range: [" + min + ", " + max + "]");

                if (cv > 0.5 && cv < 0.65 && min >= 250 && max <= 3100) {
                    console.log("  [DETECTED] Herodotus original: uniform(300,3000)");
                } else if (cv > 0.3 && cv < 0.5) {
                    console.log("  [SUSPECT] Log-normal distribution — improved variant");
                } else if (cv < 0.1) {
                    console.log("  [DETECTED] Fixed interval — naive automation");
                }
            }
        }
        return this.dispatchGesture(gesture, callback, handler);
    };

    // Also hook Random to detect jitter source
    var Random = Java.use("java.util.Random");
    Random.nextLong.implementation = function() {
        var result = this.nextLong();
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("BehaviorMimicry") !== -1 || stack.indexOf("Jitter") !== -1 ||
            stack.indexOf("Gesture") !== -1) {
            console.log("[MIMICRY] Random.nextLong() for jitter: " + result);
        }
        return result;
    };
});
```

### Sigma Rule 14: SsoHijacker Auto-Approve

```yaml
title: Accessibility Auto-Approve on SSO MFA Prompt
id: takopii-sso-hijacker-auto-approve-001
status: experimental
description: |
    Detects AccessibilityService performAction(ACTION_CLICK) on SSO app
    (Microsoft Authenticator, Okta, Duo, Google Authenticator, Authy)
    within 500ms of notification — Vespertine sub-500ms approval pattern.
    User sees notification briefly flash then disappear.
logsource:
    product: android
    category: accessibility
detection:
    sso_notification:
        event_type: 'onNotificationPosted'
        source_package|contains:
            - 'com.azure.authenticator'
            - 'com.okta.android'
            - 'com.duosecurity.duomobile'
            - 'com.google.android.apps.authenticator2'
            - 'com.authy.authy'
    auto_click:
        api_call: 'AccessibilityNodeInfo.performAction'
        action: 'ACTION_CLICK'
        text_content|contains:
            - 'approve'
            - 'allow'
            - 'confirm'
            - 'verify'
            - 'accept'
            - "it's me"
    timeframe: 1s
    condition: sso_notification | auto_click
level: critical
tags:
    - attack.credential_access
    - attack.t1517
```

### YARA Rule 12: SsoHijacker Pattern

```yara
rule Takopii_SsoHijacker_MFA_AutoApprove {
    meta:
        description = "Detects SSO MFA auto-approve pattern (Vespertine — May 2026)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1517"

    strings:
        $sso1 = "com.azure.authenticator" ascii
        $sso2 = "com.okta.android" ascii
        $sso3 = "com.duosecurity.duomobile" ascii
        $sso4 = "com.google.android.apps.authenticator2" ascii
        $sso5 = "com.authy.authy" ascii
        $approve1 = "approve" ascii nocase
        $approve2 = "confirm" ascii nocase
        $approve3 = "it's me" ascii nocase
        $approve4 = "onayla" ascii nocase
        $approve5 = "aprobar" ascii nocase
        $a11y = "AccessibilityService" ascii
        $click = "ACTION_CLICK" ascii
        $perform = "performAction" ascii

    condition:
        uint32(0) == 0x04034B50 and
        2 of ($sso1, $sso2, $sso3, $sso4, $sso5) and
        2 of ($approve1, $approve2, $approve3, $approve4, $approve5) and
        $a11y and ($click or $perform)
}
```

### Hook 23: SsoHijacker Intercept

```javascript
// Monitor SsoHijacker.autoApprove() — detect SSO MFA auto-click
Java.perform(function() {
    var ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    var ssoApps = [
        "com.azure.authenticator", "com.okta.android",
        "com.duosecurity.duomobile", "com.google.android.apps.authenticator2",
        "com.authy.authy"
    ];

    ANI.performAction.overload('int').implementation = function(action) {
        if (action === 16) { // ACTION_CLICK = 16
            var pkg = this.getPackageName();
            var pkgStr = pkg ? pkg.toString() : "";
            var text = this.getText();
            var textStr = text ? text.toString().toLowerCase() : "";

            // Check if click is on SSO app
            var isSsoApp = ssoApps.some(function(sso) {
                return pkgStr.indexOf(sso) !== -1;
            });

            var isApproveButton = ["approve", "allow", "confirm", "verify",
                "accept", "it's me", "onayla", "aprobar"]
                .some(function(p) { return textStr.indexOf(p) !== -1; });

            if (isSsoApp && isApproveButton) {
                console.log("[SSO-HIJACK] AUTO-APPROVE detected!");
                console.log("  SSO app: " + pkgStr);
                console.log("  Button text: " + textStr);
                console.log("  [CRITICAL] Vespertine MFA bypass — sub-500ms approval");
            }
        }
        return this.performAction(action);
    };
});
```

### Hook 24: TeeOffload Key + Crypto Monitor

```javascript
// Monitor TeeOffload — TEE key generation + encrypt/decrypt at call boundary
// Cannot extract keys (hardware-bound) but CAN capture plaintext at call site
Java.perform(function() {
    // Monitor key generation
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    KeyGenerator.init.overload('java.security.spec.AlgorithmParameterSpec')
        .implementation = function(params) {
        var paramsStr = params.toString();
        console.log("[TEE] KeyGenerator.init: " + paramsStr);
        if (paramsStr.indexOf("AndroidKeyStore") !== -1 ||
            paramsStr.indexOf("StrongBox") !== -1) {
            console.log("  [ALERT] TEE-backed key generation — Drelock pattern");
        }
        return this.init(params);
    };

    // Monitor Cipher operations — capture plaintext BEFORE TEE encrypt
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var mode = this.getOpmode(); // 1=ENCRYPT, 2=DECRYPT
        var algo = this.getAlgorithm();

        if (algo.indexOf("AES") !== -1 || algo.indexOf("GCM") !== -1) {
            if (mode === 1) {
                // ENCRYPT: input is plaintext — capture before TEE encrypts
                var plaintext = "";
                try {
                    plaintext = Java.use("java.lang.String").$new(input);
                } catch(e) {
                    plaintext = "<binary " + input.length + " bytes>";
                }
                console.log("[TEE] Cipher.doFinal ENCRYPT:");
                console.log("  Algorithm: " + algo);
                console.log("  Plaintext: " + plaintext.substring(0, 200));
                console.log("  [CAPTURE] Plaintext captured before TEE encryption");
            }

            var result = this.doFinal(input);

            if (mode === 2) {
                // DECRYPT: result is plaintext — capture after TEE decrypts
                var decrypted = "";
                try {
                    decrypted = Java.use("java.lang.String").$new(result);
                } catch(e) {
                    decrypted = "<binary " + result.length + " bytes>";
                }
                console.log("[TEE] Cipher.doFinal DECRYPT:");
                console.log("  Algorithm: " + algo);
                console.log("  Decrypted: " + decrypted.substring(0, 200));
            }
            return result;
        }
        return this.doFinal(input);
    };

    // Monitor KeyStore key alias creation
    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
        if (type === "AndroidKeyStore") {
            console.log("[TEE] KeyStore.getInstance('AndroidKeyStore')");
        }
        return this.getInstance(type);
    };
});
```

### Sigma Rule 15: TeeOffload Key-Encrypt-Network Chain

```yaml
title: TEE Key Generation Followed by Encrypt and Network POST
id: takopii-tee-offload-key-encrypt-net-001
status: experimental
description: |
    Detects Drelock TEE offload pattern: AndroidKeyStore key generation +
    AES-GCM encryption + network POST within 60 seconds. TEE-backed keys
    are hardware-bound — Frida cannot extract them, only capture plaintext
    at the Cipher.doFinal boundary.
logsource:
    product: android
    category: crypto
detection:
    key_gen:
        api_call|contains: 'KeyGenerator.init'
        params|contains: 'AndroidKeyStore'
    cipher_encrypt:
        api_call: 'Cipher.doFinal'
        mode: 'ENCRYPT_MODE'
        algorithm|contains:
            - 'AES/GCM'
            - 'AES_256'
    network_post:
        method: 'POST'
        content_type: 'application/octet-stream'
    timeframe: 60s
    condition: key_gen and cipher_encrypt and network_post
level: high
tags:
    - attack.defense_evasion
    - attack.t1573
```

### YARA Rule 13: YamuxProxy Multiplexer

```yara
rule Takopii_YamuxProxy_Multiplexer {
    meta:
        description = "Detects Yamux protocol multiplexer (Mirax/Klopatra tunnel pattern)"
        author = "Takopii Framework"
        severity = "high"
        specimen = "overlay-banker"
        mitre = "T1090"

    strings:
        $yamux_str = "yamux" ascii nocase
        $type_data = "TYPE_DATA" ascii
        $type_ping = "TYPE_PING" ascii
        $type_goaway = "TYPE_GO_AWAY" ascii
        $type_wup = "TYPE_WINDOW_UPDATE" ascii
        $flag_syn = "FLAG_SYN" ascii
        $flag_fin = "FLAG_FIN" ascii
        $flag_rst = "FLAG_RST" ascii
        $header_size = "HEADER_SIZE" ascii
        $stream_id = "streamId" ascii
        $mux_socket = "muxSocket" ascii
        $native_encode = "yamuxEncode" ascii
        $native_decode = "yamuxDecode" ascii

    condition:
        uint32(0) == 0x04034B50 and
        ($yamux_str or 2 of ($type_data, $type_ping, $type_goaway, $type_wup)) and
        ($flag_syn or $flag_fin) and
        ($header_size or $stream_id or $mux_socket or $native_encode)
}
```

### Hook 25: YamuxProxy Stream Monitor

```javascript
// Monitor YamuxProxy — intercept Yamux frame headers, parse stream types
// 12-byte header: [version(1), type(1), flags(2), streamId(4), length(4)]
Java.perform(function() {
    // Monitor socket output for Yamux frames
    var OutputStream = Java.use("java.io.OutputStream");
    OutputStream.write.overload('[B', 'int', 'int').implementation = function(buf, off, len) {
        // Check for Yamux header pattern
        if (len >= 12 && (buf[off] & 0xFF) === 0x00) { // Version 0
            var type = buf[off + 1] & 0xFF;
            var flags = ((buf[off + 2] & 0xFF) << 8) | (buf[off + 3] & 0xFF);
            var streamId = ((buf[off + 4] & 0xFF) << 24) | ((buf[off + 5] & 0xFF) << 16) |
                ((buf[off + 6] & 0xFF) << 8) | (buf[off + 7] & 0xFF);
            var payloadLen = ((buf[off + 8] & 0xFF) << 24) | ((buf[off + 9] & 0xFF) << 16) |
                ((buf[off + 10] & 0xFF) << 8) | (buf[off + 11] & 0xFF);

            var types = {0: "DATA", 1: "WINDOW_UPDATE", 2: "PING", 3: "GO_AWAY"};
            var flagNames = [];
            if (flags & 1) flagNames.push("SYN");
            if (flags & 2) flagNames.push("ACK");
            if (flags & 4) flagNames.push("FIN");
            if (flags & 8) flagNames.push("RST");

            console.log("[YAMUX] Frame: type=" + (types[type] || type) +
                " flags=[" + flagNames.join(",") + "]" +
                " stream=" + streamId +
                " len=" + payloadLen);

            if (type === 0 && payloadLen > 0) {
                console.log("  [DATA] " + payloadLen + " bytes on stream " + streamId);
            }
            if (flags & 1) {
                console.log("  [NEW STREAM] Stream " + streamId + " opened");
            }
        }
        return this.write(buf, off, len);
    };
});
```

### Hook 26: PerBuildObfuscation Seed Capture

```javascript
// Monitor PerBuildObfuscation — capture BUILD_SEED + derived keys
// With seed, defender can reconstruct full decode function
Java.perform(function() {
    // Hook SecureRandom to capture build seed
    var SecureRandom = Java.use("java.security.SecureRandom");
    SecureRandom.$init.overload('[B').implementation = function(seed) {
        console.log("[PERBUILD] SecureRandom seeded with " + seed.length + " bytes");
        var hex = "";
        for (var i = 0; i < seed.length; i++) {
            hex += ("0" + (seed[i] & 0xFF).toString(16)).slice(-2);
        }
        console.log("  Seed hex: " + hex);

        // Reconstruct the seed as long value
        if (seed.length === 8) {
            var value = 0;
            for (var j = 0; j < 8; j++) {
                value = value * 256 + (seed[j] & 0xFF);
            }
            console.log("  BUILD_SEED (long): " + value);
            console.log("  [CAPTURE] With this seed, defender can reconstruct xorKey, " +
                "rotAmount, addKey — full decode pipeline");
        }
        return this.$init(seed);
    };

    // Hook encode/decode methods to see transformations
    try {
        var PBO = Java.use("com.docreader.lite.stealer.frontier.PerBuildObfuscation");

        PBO.encode.implementation = function(plaintext) {
            console.log("[PERBUILD] encode('" + plaintext.substring(0, 50) + "')");
            var result = this.encode(plaintext);
            console.log("  Encoded: " + result.length + " bytes");
            return result;
        };

        PBO.decode.implementation = function(encoded) {
            var result = this.decode(encoded);
            console.log("[PERBUILD] decode -> '" + result.substring(0, 100) + "'");
            return result;
        };
    } catch(e) {}
});
```

### Sigma Rule 16: PerBuildObfuscation Seed Pattern

```yaml
title: SecureRandom Initialization with Timestamp Seed
id: takopii-perbuild-obfuscation-seed-001
status: experimental
description: |
    Detects per-build obfuscation pattern: SecureRandom initialized with
    System.currentTimeMillis as seed + Fisher-Yates shuffle + multi-layer
    encode. Apex pattern — each APK build produces unique decoder bytecode.
logsource:
    product: android
    category: crypto
detection:
    rng_init:
        api_call: 'SecureRandom.<init>'
        seed_source|contains: 'currentTimeMillis'
    multi_layer_encode:
        api_call|contains:
            - 'xorLayer'
            - 'rotLayer'
            - 'addLayer'
            - 'shuffleLayer'
    timeframe: 5s
    condition: rng_init and multi_layer_encode
level: medium
tags:
    - attack.defense_evasion
    - attack.t1027
```

### Sigma Rule 17: PlayIntegrityProbe Recon

```yaml
title: PackageManager Query for Play Integrity Components
id: takopii-play-integrity-probe-001
status: experimental
description: |
    Detects utility app scanning for Play Integrity packages
    (play.core.integrity indicators). Reconnaissance before banking
    session determines whether device passes Play Integrity check.
logsource:
    product: android
    category: package_manager
detection:
    pm_query:
        api_call|contains:
            - 'PackageManager.getPackageInfo'
            - 'PackageManager.resolveService'
        package_queried|contains:
            - 'com.google.android.gms'
            - 'play.core.integrity'
            - 'play.integrity'
    caller_not_gms:
        caller_package|not: 'com.google.android.gms'
    condition: pm_query and caller_not_gms
level: medium
tags:
    - attack.discovery
    - attack.t1418
falsepositives:
    - Apps that legitimately use Play Integrity API for device attestation
```

### Sigma Rule 18: MediaProjectionAutoConsent A11y Click

```yaml
title: Accessibility Auto-Click on MediaProjection Consent Dialog
id: takopii-mediaprojection-autoconsent-001
status: experimental
description: |
    Detects AccessibilityService performAction(ACTION_CLICK) on SystemUI
    MediaProjection consent dialog within 200ms of dialog appearance.
    Sub-200ms response time indicates automated click — human minimum is >400ms.
logsource:
    product: android
    category: accessibility
detection:
    consent_dialog:
        event_type: 'TYPE_WINDOW_STATE_CHANGED'
        source_package: 'com.android.systemui'
        class_name|contains: 'MediaProjectionPermissionActivity'
    auto_click:
        api_call: 'AccessibilityNodeInfo.performAction'
        action: 'ACTION_CLICK'
        target_package: 'com.android.systemui'
        text_content|contains:
            - 'Start now'
            - 'Start'
            - 'Allow'
    timeframe: 500ms
    condition: consent_dialog | auto_click
level: critical
tags:
    - attack.defense_evasion
    - attack.t1626
```

### Sigma Rule 19: NoteAppScraper BIP39 Detection

```yaml
title: Accessibility Text Extraction from Note App with BIP39 Word Density
id: takopii-noteapp-scraper-bip39-001
status: experimental
description: |
    Detects AccessibilityService text extraction from note-taking apps
    (Google Keep, Samsung Notes, OneNote, etc.) where extracted text
    has high BIP39 mnemonic word density (>80% in 12/24-word window).
    Perseus pattern — crypto seed phrase scraping.
logsource:
    product: android
    category: accessibility
detection:
    note_app_foreground:
        event_type: 'TYPE_WINDOW_STATE_CHANGED'
        source_package|contains:
            - 'com.google.android.keep'
            - 'com.samsung.android.app.notes'
            - 'com.microsoft.office.onenote'
            - 'com.evernote'
            - 'md.obsidian'
    text_extraction:
        api_call: 'AccessibilityNodeInfo.getText'
    bip39_density:
        text_content|re: '\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse)\b'
    timeframe: 10s
    condition: note_app_foreground and text_extraction
level: critical
tags:
    - attack.collection
    - attack.t1517
```

---

## Persistence Layer Detection

### Sigma Rule 20: EarlyInitProvider Pre-Application Init

```yaml
title: ContentProvider Pre-Application Initialization with String Decode
id: takopii-early-init-provider-001
status: experimental
description: |
    Detects ContentProvider.onCreate executing before Application.onCreate
    with string decoding (StringDecoder) and environment gate evaluation.
    ContentProvider init hook pattern — no-op provider with no real data
    operations used solely as a pre-Application init entry point.
logsource:
    product: android
    category: runtime
detection:
    provider_oncreate:
        api_call: 'ContentProvider.onCreate'
    string_decode:
        api_call|contains:
            - 'StringDecoder.xorDecode'
            - 'StringDecoder.aesDecrypt'
    env_check:
        api_call|contains:
            - 'EnvironmentGate.evaluate'
            - 'AntiEmulator.check'
    before_application:
        sequence: 'ContentProvider.onCreate BEFORE Application.onCreate'
    condition: provider_oncreate and (string_decode or env_check)
level: high
tags:
    - attack.persistence
    - attack.t1398
```

### YARA Rule 14: EarlyInitProvider No-Op Pattern

```yara
rule Takopii_EarlyInitProvider_NoOp {
    meta:
        description = "Detects ContentProvider with no-op query/insert/update/delete (init hook)"
        author = "Takopii Framework"
        severity = "medium"
        specimen = "overlay-banker"
        mitre = "T1398"

    strings:
        $provider = "ContentProvider" ascii
        $oncreate = "onCreate" ascii
        $query_null = "query" ascii
        $insert_null = "insert" ascii
        $env_gate = "EnvironmentGate" ascii
        $string_dec = "StringDecoder" ascii
        $early_init = "EarlyInit" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $provider and $oncreate and
        ($env_gate or $string_dec or $early_init)
}
```

### Hook 27: EarlyInitProvider Execution Order Monitor

```javascript
// Monitor ContentProvider.onCreate vs Application.onCreate ordering
// EarlyInitProvider runs BEFORE Application — init hook pattern
Java.perform(function() {
    var ContentProvider = Java.use("android.content.ContentProvider");
    ContentProvider.onCreate.implementation = function() {
        var className = this.getClass().getName();
        console.log("[PERSISTENCE] ContentProvider.onCreate: " + className);
        console.log("  Timestamp: " + Date.now());

        if (className.indexOf("EarlyInit") !== -1 || className.indexOf("Init") !== -1) {
            console.log("  [ALERT] Init-hook ContentProvider — pre-Application execution");
            console.log("  Stack: " + Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        return this.onCreate();
    };

    var Application = Java.use("android.app.Application");
    Application.onCreate.implementation = function() {
        console.log("[PERSISTENCE] Application.onCreate at " + Date.now());
        console.log("  (ContentProvider.onCreate already ran — compare timestamps)");
        return this.onCreate();
    };
});
```

### Sigma Rule 21: StealthFgService Low-Visibility Notification

```yaml
title: Foreground Service with Silent Notification Channel
id: takopii-stealth-fg-service-001
status: experimental
description: |
    Detects foreground service started with low-visibility notification:
    silent channel (no sound/vibrate), min-priority, or hidden notification.
    Banker FG service uses benign notification text as cover for persistence.
logsource:
    product: android
    category: service
detection:
    fg_start:
        api_call: 'Service.startForeground'
    low_visibility:
        notification_importance|lte: 1
        notification_sound: false
        notification_vibrate: false
    boot_chain:
        preceding_event: 'BOOT_COMPLETED'
    timeframe: 60s
    condition: fg_start and (low_visibility or boot_chain)
level: high
tags:
    - attack.persistence
    - attack.t1398
```

### Sigma Rule 22: BootReceiver Persistence Chain

```yaml
title: Boot Receiver to FG Service to Network Activity Chain
id: takopii-boot-receiver-chain-001
status: experimental
description: |
    Detects BOOT_COMPLETED receiver triggering foreground service start
    followed by network activity within 60 seconds of device boot.
    Includes LOCKED_BOOT_COMPLETED (direct-boot aware) and
    MY_PACKAGE_REPLACED (survives app updates) variants.
logsource:
    product: android
    category: receiver
detection:
    boot_event:
        intent_action|contains:
            - 'BOOT_COMPLETED'
            - 'LOCKED_BOOT_COMPLETED'
            - 'MY_PACKAGE_REPLACED'
    fg_service_start:
        api_call|contains:
            - 'startForegroundService'
            - 'startService'
    network_activity:
        method|contains:
            - 'GET'
            - 'POST'
    timeframe: 60s
    condition: boot_event | fg_service_start | network_activity
level: high
tags:
    - attack.persistence
    - attack.t1398
falsepositives:
    - Messaging apps that reconnect to push servers on boot
    - Weather apps that refresh on boot (check permission combo)
```

### dumpsys Enhancement for Persistence

```bash
# Enhanced persistence detection commands

# Check boot receivers
adb shell dumpsys package com.docreader.lite | grep -A3 "BOOT_COMPLETED"
adb shell dumpsys package com.docreader.lite | grep -A3 "LOCKED_BOOT_COMPLETED"
adb shell dumpsys package com.docreader.lite | grep -A3 "MY_PACKAGE_REPLACED"

# Active foreground services with notification details
adb shell dumpsys activity services com.docreader.lite | grep -E "isForeground|foreground|notification"

# ContentProvider execution order (check attachInfo timestamps)
adb shell dumpsys activity providers com.docreader.lite

# Alarm/job scheduling (persistence re-arm)
adb shell dumpsys alarm | grep -E "docreader|skyweather|cleanmaster"
adb shell dumpsys jobscheduler | grep -E "docreader|skyweather|cleanmaster"
```

---

## Spread Module Detection

### Hook 28: ContactHarvester Monitor

```javascript
// Monitor ContactHarvester — detects contact list exfiltration
// Catches: ContentResolver.query on ContactsContract + batch collection
Java.perform(function() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
        '[Ljava.lang.String;', 'java.lang.String'
    ).implementation = function(uri, proj, sel, selArgs, sort) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("contacts") !== -1 || uriStr.indexOf("phone") !== -1 ||
            uriStr.indexOf("ContactsContract") !== -1) {
            var callerPkg = Java.use("android.app.ActivityThread")
                .currentApplication().getApplicationContext().getPackageName();
            console.log("[HARVEST] Contact query from: " + callerPkg);
            console.log("  URI: " + uriStr);
            console.log("  Projection: " + (proj ? proj.join(", ") : "all"));
            console.log("  Sort: " + sort);

            // Count results to detect bulk harvest
            var cursor = this.query(uri, proj, sel, selArgs, sort);
            if (cursor !== null) {
                var count = cursor.getCount();
                console.log("  Results: " + count + " contacts");
                if (count > 10) {
                    console.log("  [ALERT] Bulk contact harvest — " + count +
                        " contacts queried by non-contacts app");
                }
            }
            return cursor;
        }
        return this.query(uri, proj, sel, selArgs, sort);
    };
});
```

### Sigma Rule 23: ContactHarvester Bulk Query + Exfil

```yaml
title: Contact List Query Followed by Network Exfiltration
id: takopii-contact-harvester-bulk-001
status: experimental
description: |
    Detects ContentResolver query on ContactsContract from non-contacts app
    followed by network POST within 120 seconds. FluBot pattern: harvest
    contacts for SMS worm spreading + social graph intelligence.
logsource:
    product: android
    category: content_resolver
detection:
    contacts_query:
        uri|contains:
            - 'content://com.android.contacts'
            - 'ContactsContract'
        caller_package|not:
            - 'com.google.android.contacts'
            - 'com.samsung.android.contacts'
            - 'com.android.contacts'
    network_exfil:
        method: 'POST'
        body|contains: 'phone'
    timeframe: 120s
    condition: contacts_query | network_exfil
level: high
tags:
    - attack.collection
    - attack.t1636
```

### Hook 29: SmsWorm Rate-Limited Spread Monitor

```javascript
// Monitor SmsWorm — detect rate-limited SMS spreading
// FluBot pattern: 1 SMS per 30-60s to avoid carrier detection
Java.perform(function() {
    var smsSendTimes = [];
    var smsDestinations = [];

    // Hook SmsManager.sendTextMessage
    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.overload(
        'java.lang.String', 'java.lang.String', 'java.lang.String',
        'android.app.PendingIntent', 'android.app.PendingIntent'
    ).implementation = function(dest, sc, body, sentIntent, deliveryIntent) {
        var now = Date.now();
        smsSendTimes.push(now);
        smsDestinations.push(dest);

        console.log("[SMS-WORM] sendTextMessage:");
        console.log("  Destination: " + dest);
        console.log("  Body: " + body.substring(0, 100));
        console.log("  Total sent this session: " + smsSendTimes.length);

        // Rate analysis
        if (smsSendTimes.length > 1) {
            var delta = (now - smsSendTimes[smsSendTimes.length - 2]) / 1000;
            console.log("  Time since last: " + delta.toFixed(1) + "s");

            if (delta >= 25 && delta <= 65) {
                console.log("  [ALERT] Rate-limited spreading pattern (30-60s interval)");
            }
        }

        // Unique destination analysis
        var unique = [];
        smsDestinations.forEach(function(d) {
            if (unique.indexOf(d) === -1) unique.push(d);
        });
        if (unique.length > 5) {
            console.log("  [CRITICAL] SMS sent to " + unique.length +
                " unique recipients — worm spreading!");
        }

        // URL detection in body
        if (body.match(/https?:\/\/[^\s]+/)) {
            console.log("  [ALERT] URL in SMS body — install-link lure");
        }

        return this.sendTextMessage(dest, sc, body, sentIntent, deliveryIntent);
    };

    // Also hook reflection-based SMS sending (ReflectionHider.sendSms)
    var Method = Java.use("java.lang.reflect.Method");
    Method.invoke.implementation = function(obj, args) {
        var methodName = this.getName();
        if (methodName === "sendTextMessage" && args && args.length >= 3) {
            console.log("[SMS-WORM-REFLECT] SMS via reflection to: " + args[0]);
        }
        return this.invoke(obj, args);
    };
});
```

### YARA Rule 15: SmsWorm Lure + SMS Send

```yara
rule Takopii_SmsWorm_Spreading {
    meta:
        description = "Detects SMS worm with lure templates and contact-targeted spreading"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1582"

    strings:
        $sms_send = "sendTextMessage" ascii
        $sms_multi = "sendMultipartTextMessage" ascii
        $contacts = "ContactsContract" ascii
        $lure1 = "package delivery" ascii nocase
        $lure2 = "pending payment" ascii nocase
        $lure3 = "verify your account" ascii nocase
        $lure4 = "shared photos" ascii nocase
        $template = "{name}" ascii
        $url_placeholder = "{url}" ascii
        $rate_limit = "delay" ascii

    condition:
        uint32(0) == 0x04034B50 and
        ($sms_send or $sms_multi) and
        $contacts and
        (2 of ($lure1, $lure2, $lure3, $lure4) or ($template and $url_placeholder))
}
```

---

## Stage-1 Core Deep Detection

Detection targeting the stage-1-evasion (SkyWeather) specimen's kill chain core.

### Hook 30: AccessibilityEngine Gate Monitor

```javascript
// Monitor AccessibilityEngine gate evaluation
// Captures: dormancy check, interaction threshold, RFC1918 validation
Java.perform(function() {
    try {
        var AppConfig = Java.use("com.skyweather.forecast.core.AppConfig");

        // Monitor endpoint safety check (RFC1918 gate)
        AppConfig.isEndpointSafe.implementation = function() {
            var result = this.isEndpointSafe();
            console.log("[GATE] AppConfig.isEndpointSafe() = " + result);
            if (!result) {
                console.log("  [GATE-FAIL] Endpoint is not RFC1918 — stealer disabled");
            }
            return result;
        };
    } catch(e) {}

    // Monitor AccessibilityService onServiceConnected (arming)
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    AccessibilityService.onServiceConnected.implementation = function() {
        console.log("[A11Y-GATE] AccessibilityService.onServiceConnected()");
        console.log("  Service armed — will now receive all UI events");
        return this.onServiceConnected();
    };
});
```

### Hook 31: CredentialStore Buffer Monitor

```javascript
// Monitor CredentialStore — capture/drain/peekAll operations
// Alert on drain (exfil flush) and peekAll (ATS OTP lookup)
Java.perform(function() {
    try {
        var CredentialStore = Java.use("com.skyweather.forecast.core.CredentialStore");

        CredentialStore.capture.implementation = function(event) {
            console.log("[CREDSTORE] capture: pkg=" + event.packageName.value +
                " type=" + event.eventType.value +
                " text_len=" + event.text.value.length);
            console.log("  Buffer size: " + this.size());
            return this.capture(event);
        };

        CredentialStore.drain.implementation = function() {
            var result = this.drain();
            console.log("[CREDSTORE] drain() — " + result.size() + " events flushed for exfil");
            if (result.size() > 0) {
                console.log("  [ALERT] Credential buffer drained — exfil in progress");
            }
            return result;
        };

        CredentialStore.peekAll.implementation = function() {
            var result = this.peekAll();
            console.log("[CREDSTORE] peekAll() — " + result.size() +
                " events (non-destructive read)");
            console.log("  [ATS] OTP lookup — scanning buffer for latest OTP entry");
            return result;
        };
    } catch(e) {
        console.log("[CREDSTORE] Not in this specimen: " + e);
    }
});
```

### Hook 32: NotificationEngine 5-Point Extraction Monitor

```javascript
// Enhanced NLS monitor — captures all 5 extraction points:
// EXTRA_TITLE, EXTRA_TEXT, EXTRA_BIG_TEXT, EXTRA_SUB_TEXT, tickerText
Java.perform(function() {
    var NLS = Java.use("android.service.notification.NotificationListenerService");

    NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification')
        .implementation = function(sbn) {
        var pkg = sbn.getPackageName();
        var notification = sbn.getNotification();
        var extras = notification.extras;

        // All 5 extraction points
        var title = extras.getCharSequence("android.title");
        var text = extras.getCharSequence("android.text");
        var bigText = extras.getCharSequence("android.bigText");
        var subText = extras.getCharSequence("android.subText");
        var ticker = notification.tickerText;

        console.log("[NLS-5PT] Notification from: " + pkg);
        console.log("  [1] EXTRA_TITLE: " + (title ? title.toString().substring(0, 50) : "null"));
        console.log("  [2] EXTRA_TEXT: " + (text ? text.toString().substring(0, 50) : "null"));
        console.log("  [3] EXTRA_BIG_TEXT: " + (bigText ? bigText.toString().substring(0, 50) : "null"));
        console.log("  [4] EXTRA_SUB_TEXT: " + (subText ? subText.toString().substring(0, 50) : "null"));
        console.log("  [5] tickerText: " + (ticker ? ticker.toString().substring(0, 50) : "null"));

        // Check which extraction point yields OTP
        var allText = [title, text, bigText, subText, ticker]
            .filter(function(t) { return t !== null; })
            .map(function(t) { return t.toString(); })
            .join(" ");

        var otpMatch = allText.match(/\b\d{4,8}\b/);
        if (otpMatch) {
            console.log("  [OTP] Code found: " + otpMatch[0]);
            // Identify which extraction point contained the OTP
            [["EXTRA_TITLE", title], ["EXTRA_TEXT", text],
             ["EXTRA_BIG_TEXT", bigText], ["EXTRA_SUB_TEXT", subText],
             ["tickerText", ticker]].forEach(function(pair) {
                if (pair[1] && pair[1].toString().indexOf(otpMatch[0]) !== -1) {
                    console.log("  [OTP SOURCE] Extracted from: " + pair[0]);
                }
            });
        }

        return this.onNotificationPosted(sbn);
    };
});
```

### Hook 33: SmsInterceptor Priority Monitor

```javascript
// Monitor SmsInterceptor — detect high-priority SMS receiver
// Priority 999 = intercept-first pattern (fires before legit SMS app)
Java.perform(function() {
    var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");

    BroadcastReceiver.onReceive.implementation = function(context, intent) {
        var action = intent.getAction();
        if (action && action.indexOf("SMS_RECEIVED") !== -1) {
            console.log("[SMS-INTERCEPT] onReceive: " + action);
            console.log("  Receiver: " + this.getClass().getName());
            console.log("  Is ordered: " + this.isOrderedBroadcast());

            // Check for abortBroadcast (suppresses notification)
            var origAbort = this.getAbortBroadcast.bind(this);
        }
        var result = this.onReceive(context, intent);

        // Check if broadcast was aborted (SMS suppression)
        if (action && action.indexOf("SMS_RECEIVED") !== -1) {
            if (this.getAbortBroadcast()) {
                console.log("  [CRITICAL] abortBroadcast() called — SMS notification suppressed!");
            }
        }
        return result;
    };

    // Also monitor multi-part SMS concatenation
    var SmsMessage = Java.use("android.telephony.SmsMessage");
    SmsMessage.createFromPdu.overload('[B', 'java.lang.String').implementation = function(pdu, format) {
        var msg = this.createFromPdu(pdu, format);
        if (msg !== null) {
            console.log("[SMS-INTERCEPT] SmsMessage parsed:");
            console.log("  From: " + msg.getOriginatingAddress());
            console.log("  Body length: " + (msg.getMessageBody() ?
                msg.getMessageBody().length() : 0));
        }
        return msg;
    };
});
```

### Hook 34: OtpExtractor Confidence Scoring Monitor

```javascript
// Monitor OtpExtractor — 3-pass confidence scoring
// Captures: confidence level (HIGH/MEDIUM/LOW), matched keywords, context
Java.perform(function() {
    try {
        var OtpExtractor = Java.use("com.skyweather.forecast.core.OtpExtractor");

        OtpExtractor.extract.implementation = function(text) {
            var result = this.extract(text);
            if (result !== null) {
                console.log("[OTP-EXTRACT] extract():");
                console.log("  Code: " + result.code.value);
                console.log("  Confidence: " + result.confidence.value);
                console.log("  Input text (first 80): '" + text.substring(0, 80) + "'");
            }
            return result;
        };

        // If extractAll exists (overlay-banker variant)
        try {
            OtpExtractor.extractAll.implementation = function(text) {
                var results = this.extractAll(text);
                console.log("[OTP-EXTRACT] extractAll() found " +
                    results.size() + " codes in text");
                for (var i = 0; i < results.size(); i++) {
                    var r = results.get(i);
                    console.log("  [" + (i + 1) + "] code=" + r.code.value +
                        " confidence=" + r.confidence.value);
                }
                return results;
            };
        } catch(e) {}
    } catch(e) {
        // Try overlay-banker package
        try {
            var OtpExtractor2 = Java.use("com.docreader.lite.stealer.OtpExtractor");
            OtpExtractor2.extract.implementation = function(text) {
                var result = this.extract(text);
                if (result !== null) {
                    console.log("[OTP-EXTRACT] extract: code=" + result.code.value +
                        " confidence=" + result.confidence.value);
                }
                return result;
            };
        } catch(e2) {}
    }
});
```

### Hook 35b: ScreenReader A11y Tree Traversal Monitor

```javascript
// Monitor ScreenReader — A11y tree traversal for ATS screen-reading
// ScreenReader is ATS's "eyes": getRootInActiveWindow() + recursive getChild()
// traverses the ENTIRE foreground app's UI hierarchy.
// Detects: screen-state identification, balance extraction, IBAN reading,
//          button enumeration for automated transfer flow
//
// Source: com.skyweather.forecast.core.ScreenReader (stage-1-evasion)
// Analyst tell: recursive getChild() from non-foreground package = banker screen-reading
Java.perform(function() {
    // ── Monitor getRootInActiveWindow (the entry point) ──
    var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    AccessibilityService.getRootInActiveWindow.overload()
        .implementation = function() {
        var root = this.getRootInActiveWindow();
        if (root !== null) {
            var pkg = root.getPackageName();
            console.log("[SCREEN-READ] getRootInActiveWindow() → pkg=" + pkg);
            console.log("  [ATS-EYES] Tree root obtained — full screen scrape imminent");
            console.log("  childCount=" + root.getChildCount());
        }
        return root;
    };

    // ── Monitor AccessibilityNodeInfo.getChild (recursive traversal) ──
    var childCallCount = 0;
    var lastTreePkg = "";
    var lastTreeTime = 0;
    var NodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

    NodeInfo.getChild.overload('int').implementation = function(index) {
        var child = this.getChild(index);
        childCallCount++;

        // Log on first call of each traversal burst (>200ms gap = new traversal)
        var now = Date.now();
        if (now - lastTreeTime > 200) {
            if (childCallCount > 1) {
                console.log("[SCREEN-READ] Previous traversal: " + childCallCount +
                    " getChild() calls on pkg=" + lastTreePkg);
                if (childCallCount > 50) {
                    console.log("  [ALERT] Deep tree traversal (>" + childCallCount +
                        " nodes) — ATS full-screen reading pattern");
                }
            }
            childCallCount = 1;
            var pkg = this.getPackageName();
            lastTreePkg = pkg ? pkg.toString() : "unknown";
        }
        lastTreeTime = now;

        return child;
    };

    // ── Monitor findAccessibilityNodeInfosByViewId (targeted element lookup) ──
    NodeInfo.findAccessibilityNodeInfosByViewId.implementation = function(viewId) {
        var result = this.findAccessibilityNodeInfosByViewId(viewId);
        console.log("[SCREEN-READ] findByViewId: '" + viewId + "' → " +
            (result ? result.size() : 0) + " matches");
        // ATS pattern: searching for known banking app view IDs
        // e.g. "com.example.bank:id/amount_field", "com.example.bank:id/confirm_button"
        if (viewId && (viewId.indexOf("amount") !== -1 || viewId.indexOf("iban") !== -1 ||
            viewId.indexOf("confirm") !== -1 || viewId.indexOf("transfer") !== -1 ||
            viewId.indexOf("otp") !== -1 || viewId.indexOf("pin") !== -1 ||
            viewId.indexOf("password") !== -1 || viewId.indexOf("balance") !== -1)) {
            console.log("  [ATS-TARGET] Banking-relevant view ID searched");
        }
        return result;
    };

    // ── Monitor findAccessibilityNodeInfosByText (text-based screen detection) ──
    NodeInfo.findAccessibilityNodeInfosByText.implementation = function(text) {
        var result = this.findAccessibilityNodeInfosByText(text);
        console.log("[SCREEN-READ] findByText: '" + text + "' → " +
            (result ? result.size() : 0) + " matches");
        // ATS screen-state detection: checking for navigation keywords
        var lower = text.toLowerCase();
        if (lower.indexOf("transfer") !== -1 || lower.indexOf("confirm") !== -1 ||
            lower.indexOf("code") !== -1 || lower.indexOf("successful") !== -1 ||
            lower.indexOf("verify") !== -1 || lower.indexOf("balance") !== -1) {
            console.log("  [ATS-STATE] Screen-state detection keyword searched");
        }
        return result;
    };

    // ── Monitor performAction — the ATS execution phase ──
    NodeInfo.performAction.overload('int').implementation = function(action) {
        var actionName = "unknown";
        switch(action) {
            case 16: actionName = "ACTION_CLICK"; break;
            case 32: actionName = "ACTION_LONG_CLICK"; break;
            case 64: actionName = "ACTION_FOCUS"; break;
            case 4096: actionName = "ACTION_SCROLL_FORWARD"; break;
            case 8192: actionName = "ACTION_SCROLL_BACKWARD"; break;
        }
        var viewId = this.getViewIdResourceName();
        var text = this.getText();
        console.log("[SCREEN-READ] performAction: " + actionName +
            " on viewId=" + (viewId || "none") +
            " text='" + (text ? text.toString().substring(0, 30) : "") + "'");

        if (action === 16) { // ACTION_CLICK
            console.log("  [ATS-INJECT] Synthetic click injected via performAction");
        }
        return this.performAction(action);
    };

    // ── Monitor ACTION_SET_TEXT (credential auto-fill) ──
    NodeInfo.performAction.overload('int', 'android.os.Bundle').implementation = function(action, args) {
        if (action === 0x200000) { // ACTION_SET_TEXT = 2097152 = 0x200000
            var setText = args ? args.getCharSequence("ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE") : null;
            var viewId = this.getViewIdResourceName();
            console.log("[SCREEN-READ] ACTION_SET_TEXT:");
            console.log("  viewId=" + (viewId || "none"));
            console.log("  text_len=" + (setText ? setText.length() : 0));
            // Don't log actual text (could be OTP or credential)
            // But DO flag the field type
            if (viewId) {
                var vid = viewId.toLowerCase();
                if (vid.indexOf("amount") !== -1) {
                    console.log("  [ATS-FILL] Amount field filled — transfer in progress");
                } else if (vid.indexOf("iban") !== -1 || vid.indexOf("account") !== -1 ||
                           vid.indexOf("recipient") !== -1) {
                    console.log("  [ATS-FILL] Recipient field filled — mule account injection");
                } else if (vid.indexOf("otp") !== -1 || vid.indexOf("code") !== -1 ||
                           vid.indexOf("pin") !== -1) {
                    console.log("  [ATS-FILL] OTP/PIN field filled — intercepted code auto-filled");
                }
            }
        }
        return this.performAction(action, args);
    };
});
```

### Sigma Rule 24: ScreenReader Full-Tree Traversal During Banking Session

```yaml
title: Full Accessibility Tree Traversal During Banking App Session
id: tak-screenreader-tree-traversal
status: experimental
description: >
    Detects when an accessibility service performs deep tree traversal
    (getRootInActiveWindow + >50 getChild calls) while a banking app
    is in foreground. ScreenReader.extractAllText() recurses the entire
    view hierarchy to read balances, IBANs, and screen-state text.
    Normal A11y screen readers don't traverse 50+ nodes in <200ms bursts.
references:
    - specimens/stage-1-evasion/../core/ScreenReader.kt
    - ANALYSIS.md §5.1 — Accessibility Service Abuse
    - MITRE ATT&CK T1517 — Access Notifications
author: Takopii Detection Engineering
date: 2026/05/12
logsource:
    product: android
    service: frida-monitor
detection:
    tree_root:
        EventType: "getRootInActiveWindow"
        SourcePackage|contains:
            - "skyweather"
            - "docreader"
    deep_traversal:
        EventType: "getChild"
        CallCount|gte: 50
    banking_foreground:
        ForegroundPackage|contains:
            - "dvbank"
            - "bank"
            - "finance"
            - "pago"
    condition: tree_root and deep_traversal and banking_foreground
    timeframe: 2s
falsepositives:
    - Legitimate accessibility screen readers (TalkBack) — but these don't
      target specific banking-related view IDs in their queries
    - Accessibility testing frameworks (Espresso) during development
level: critical
tags:
    - attack.collection
    - attack.t1517
```

### YARA Rule 16: ScreenReader Recursive getChild Pattern

```
rule ScreenReader_ATS_TreeTraversal {
    meta:
        description = "Detects AccessibilityNodeInfo recursive tree traversal pattern used for ATS screen reading"
        author = "Takopii Detection Engineering"
        reference = "specimens/stage-1-evasion/../core/ScreenReader.kt"
        family = "SkyWeather/Anatsa-shape"

    strings:
        // ScreenReader method signatures
        $getRootInActiveWindow = "getRootInActiveWindow"
        $getChild = "getChild"
        $viewIdResourceName = "viewIdResourceName"
        $findNodeById = "findNodeById"
        $findNodeByText = "findNodeByText"
        $extractAllText = "extractAllText"
        $findClickableNodes = "findClickableNodes"
        $findEditableNodes = "findEditableNodes"

        // Screen-state detection keywords (ATS navigation)
        $screen_transfer = "Transfer" ascii
        $screen_confirm = "Confirm" ascii
        $screen_code = "code" ascii
        $screen_successful = "Successful" ascii

        // ATS composition: tree traversal + action dispatch
        $performAction = "performAction"
        $ACTION_SET_TEXT = "ACTION_SET_TEXT"
        $ACTION_CLICK = "ACTION_CLICK"

    condition:
        androguard.package_name(/skyweather|docreader/) and
        $getRootInActiveWindow and $getChild and
        (
            // Full ScreenReader shape: tree traversal + text extraction
            ($viewIdResourceName and 2 of ($findNodeById, $findNodeByText, $extractAllText,
                $findClickableNodes, $findEditableNodes)) or
            // ATS composition: read screen + inject actions
            ($getRootInActiveWindow and $getChild and $performAction and
                ($ACTION_SET_TEXT or $ACTION_CLICK) and
                2 of ($screen_transfer, $screen_confirm, $screen_code, $screen_successful))
        )
}
```

---

## DGA Precomputation Script

Defender-side precomputation of SharkBot V2.8 DGA domains. Run weekly to sinkhole candidates before attacker infrastructure activates.

```python
#!/usr/bin/env python3
"""
DGA Precomputation — SharkBot V2.8 Algorithm
Generates all candidate domains for future weeks.
Defender sinkhole/monitor these BEFORE the week begins.

Algorithm (from DomainResolver.kt / research/06):
  seed = TLD + ISO_week_number + calendar_year
  hash = MD5(seed).hexdigest()[:16]
  domain = hash + TLD
  7 TLDs = 7 candidates per week

Lab variant (SkyWeather specimen) generates RFC1918 IPs instead:
  Each octet = int(hash[2*i:2*i+2], 16) % range + base
  Constrained to 10.x.y.z private address space
"""

import hashlib
from datetime import datetime, timedelta

TLDS = [".xyz", ".live", ".com", ".store", ".info", ".top", ".net"]


def generate_dga_domains(week_number: int, year: int) -> list[str]:
    """Generate 7 DGA domains for a given ISO week."""
    domains = []
    for tld in TLDS:
        seed = f"{tld}{week_number}{year}"
        md5 = hashlib.md5(seed.encode()).hexdigest()[:16]
        domains.append(f"{md5}{tld}")
    return domains


def generate_dga_ips(week_number: int, year: int) -> list[str]:
    """Generate DGA-derived RFC1918 IPs (lab variant)."""
    ips = []
    for tld in TLDS:
        seed = f"{tld}{week_number}{year}"
        md5 = hashlib.md5(seed.encode()).hexdigest()
        octets = [
            10,  # Fixed first octet (RFC1918)
            int(md5[0:2], 16) % 256,
            int(md5[2:4], 16) % 256,
            int(md5[4:6], 16) % 254 + 1,  # 1-254 (no .0 or .255)
        ]
        port = 8080 + (int(md5[6:8], 16) % 920)  # 8080-8999
        ips.append(f"{'.'.join(map(str, octets))}:{port}")
    return ips


def precompute_weeks(num_weeks: int = 52):
    """Precompute DGA candidates for next N weeks."""
    now = datetime.now()
    print(f"DGA Precomputation — SharkBot V2.8")
    print(f"Generated: {now.isoformat()}")
    print(f"Weeks: {num_weeks}")
    print("=" * 72)

    for i in range(num_weeks):
        dt = now + timedelta(weeks=i)
        week = dt.isocalendar()[1]
        year = dt.isocalendar()[0]

        domains = generate_dga_domains(week, year)
        ips = generate_dga_ips(week, year)

        marker = " <-- CURRENT" if i == 0 else ""
        print(f"\nWeek {week}/{year}{marker}")
        print(f"  Domains: {', '.join(domains)}")
        print(f"  Lab IPs: {', '.join(ips)}")


def export_sinkhole_list(num_weeks: int = 12, output: str = "sinkhole.txt"):
    """Export flat domain list for DNS sinkhole import."""
    now = datetime.now()
    domains = set()
    for i in range(num_weeks):
        dt = now + timedelta(weeks=i)
        week = dt.isocalendar()[1]
        year = dt.isocalendar()[0]
        domains.update(generate_dga_domains(week, year))

    with open(output, "w") as f:
        for domain in sorted(domains):
            f.write(domain + "\n")
    print(f"Exported {len(domains)} domains to {output}")


if __name__ == "__main__":
    precompute_weeks(12)  # Next 12 weeks
    export_sinkhole_list(12)
```

Usage:
```bash
python3 dga_precompute.py
# Output: domain candidates + lab IPs for next 12 weeks
# sinkhole.txt: flat list for DNS sinkhole / firewall blocklist import
```

---

## UpdateChannel Config Interception

### Hook 35: UpdateChannel Response Capture

```javascript
// Monitor UpdateChannel — intercept /api/v1/update response
// Captures: newC2Host, newC2Port, newTargets, newPayloadUrl, killBotIds
// Alert on C2 rotation and target list updates
Java.perform(function() {
    // Hook HTTP response body reading for update endpoint
    var BufferedReader = Java.use("java.io.BufferedReader");
    var InputStreamReader = Java.use("java.io.InputStreamReader");

    // Track active URL for context
    var activeUrl = "";
    var URL = Java.use("java.net.URL");
    URL.$init.overload('java.lang.String').implementation = function(url) {
        if (url.indexOf("/api/v1/update") !== -1 || url.indexOf("/api/v1/config") !== -1 ||
            url.indexOf("/api/v1/commands") !== -1) {
            activeUrl = url;
            console.log("[UPDATE-CH] Config/update request: " + url);
        }
        return this.$init(url);
    };

    // Capture JSON response parsing
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.$init.overload('java.lang.String').implementation = function(json) {
            if (activeUrl.indexOf("/api/v1/") !== -1) {
                console.log("[UPDATE-CH] JSON response parsed:");
                var jsonStr = json.length > 500 ? json.substring(0, 500) + "..." : json;
                console.log("  Body: " + jsonStr);

                // Parse known UpdateConfig fields
                try {
                    var obj = this.$init(json);
                    if (obj.has("c2_host") || obj.has("newC2Host")) {
                        console.log("  [C2-ROTATE] New C2 host: " +
                            (obj.optString("c2_host") || obj.optString("newC2Host")));
                    }
                    if (obj.has("c2_port") || obj.has("newC2Port")) {
                        console.log("  [C2-ROTATE] New C2 port: " +
                            (obj.optInt("c2_port") || obj.optInt("newC2Port")));
                    }
                    if (obj.has("targets") || obj.has("newTargets")) {
                        console.log("  [TARGETS] Target list update: " +
                            (obj.optString("targets") || obj.optString("newTargets")));
                    }
                    if (obj.has("payload_url") || obj.has("newPayloadUrl")) {
                        console.log("  [PAYLOAD] New payload URL: " +
                            (obj.optString("payload_url") || obj.optString("newPayloadUrl")));
                    }
                    if (obj.has("kill") || obj.has("killBotIds")) {
                        console.log("  [KILL] Kill switch for bot IDs: " +
                            (obj.optString("kill") || obj.optString("killBotIds")));
                    }
                    return obj;
                } catch(e) {}
            }
            return this.$init(json);
        };
    } catch(e) {}

    // Monitor OkHttp responses (overlay-banker uses OkHttp)
    try {
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        ResponseBody.string.implementation = function() {
            var body = this.string();
            if (body.indexOf("c2_host") !== -1 || body.indexOf("targets") !== -1 ||
                body.indexOf("payload_url") !== -1 || body.indexOf("kill") !== -1) {
                console.log("[UPDATE-CH] OkHttp response with config fields:");
                console.log("  Body: " + body.substring(0, 300));
            }
            return body;
        };
    } catch(e) {}
});
```

---

## Corpus Completion — Additional Detection Rules

YARA Rules 18-24 and Sigma Rules 27-34 close the gap to the 95-rule corpus (24 YARA + 34 Sigma + 37 Frida). These cover evasion primitives, frontier modules, and cross-specimen behavioral patterns not addressed by the per-specimen sections above.

### YARA Rule 18: BehaviorMimicry Herodotus Jitter Constants

```
rule Takopii_BehaviorMimicry_Jitter {
    meta:
        description = "Detects Herodotus-pattern behavior mimicry — uniform(300,3000) jitter"
        author = "Takopii Detection Corpus"
        family = "Herodotus / Apex"
        mitre = "T1407"
        specimen = "stage-1-evasion"

    strings:
        // Jitter bound constants (300ms lower, 3000ms upper)
        $jitter_low  = { 2C 01 00 00 }  // 300 as int32 LE
        $jitter_high = { B8 0B 00 00 }  // 3000 as int32 LE

        // Random generator patterns
        $random1 = "nextInt" ascii
        $random2 = "nextLong" ascii
        $random3 = "ThreadLocalRandom" ascii

        // Delay execution
        $delay1 = "Thread.sleep" ascii
        $delay2 = "delay" ascii
        $delay3 = "postDelayed" ascii

        // Behavior mimicry — gesture dispatch
        $mimic1 = "dispatchGesture" ascii
        $mimic2 = "performAction" ascii
        $mimic3 = "TYPE_VIEW_CLICKED" ascii

    condition:
        uint32(0) == 0x0A786564
        and ($jitter_low and $jitter_high)
        and (1 of ($random*))
        and (1 of ($delay*))
        and (1 of ($mimic*))
}
```

**Match rationale:** Herodotus timing jitter uses `uniform(300, 3000)` constants alongside Random + delay + gesture injection. Legitimate apps don't combine random-delay timing with gesture dispatch. Low FP.

### YARA Rule 19: TeeOffload AndroidKeyStore + TEE Dispatch

```
rule Takopii_TeeOffload_KeyStore {
    meta:
        description = "Detects TEE/TrustZone offload — AndroidKeyStore + hardware-backed key ops + network exfil"
        author = "Takopii Detection Corpus"
        family = "Drelock"
        mitre = "T1573.002"
        specimen = "stage-1-evasion"

    strings:
        // AndroidKeyStore TEE binding
        $ks1 = "AndroidKeyStore" ascii
        $ks2 = "setIsStrongBoxBacked" ascii
        $ks3 = "setUserAuthenticationRequired" ascii

        // KeyGenParameterSpec
        $kg1 = "KeyGenParameterSpec" ascii
        $kg2 = "PURPOSE_ENCRYPT" ascii
        $kg3 = "PURPOSE_SIGN" ascii

        // TEE security level
        $tee1 = "SECURITY_LEVEL_TRUSTED_ENVIRONMENT" ascii
        $tee2 = "SECURITY_LEVEL_STRONGBOX" ascii
        $tee3 = "isInsideSecureHardware" ascii

        // Post-encrypt network exfil
        $net1 = "HttpURLConnection" ascii
        $net2 = "OkHttpClient" ascii
        $net3 = "openConnection" ascii

        // Cipher
        $cipher1 = "Cipher.getInstance" ascii
        $cipher2 = "AES/GCM/NoPadding" ascii

    condition:
        uint32(0) == 0x0A786564
        and (2 of ($ks*))
        and (1 of ($kg*))
        and (1 of ($tee*))
        and (1 of ($net*))
        and (1 of ($cipher*))
}
```

**Match rationale:** Drelock-class TEE offload generates hardware-backed keys, encrypts stolen data in TEE context, exfils immediately. Legitimate apps use AndroidKeyStore for key storage but rarely combine it with immediate network POST of encrypted data. FP: enterprise MDM apps that escrow keys — verify with other banker indicators.

### YARA Rule 20: CertPinnerProbe TLS Fingerprinting

```
rule Takopii_CertPinnerProbe {
    meta:
        description = "Detects SSL/TLS certificate pinning probe — enumeration of target app pinning"
        author = "Takopii Detection Corpus"
        family = "Generic banker recon"
        mitre = "T1521"
        specimen = "stage-1-evasion"

    strings:
        // OkHttp pinning
        $pin1 = "CertificatePinner" ascii
        $pin2 = "sha256/" ascii
        $pin3 = "check(" ascii

        // Network Security Config
        $nsc1 = "network_security_config" ascii
        $nsc2 = "pin-set" ascii
        $nsc3 = "trust-anchors" ascii

        // TrustManager manipulation
        $tm1 = "X509TrustManager" ascii
        $tm2 = "checkServerTrusted" ascii
        $tm3 = "getAcceptedIssuers" ascii

        // SSLContext custom init
        $ssl1 = "SSLContext.getInstance" ascii
        $ssl2 = "TLSv1.2" ascii
        $ssl3 = "TLSv1.3" ascii

        // Certificate inspection
        $cert1 = "getEncoded" ascii
        $cert2 = "X509Certificate" ascii
        $cert3 = "getSubjectDN" ascii
        $cert4 = "getIssuerDN" ascii

    condition:
        uint32(0) == 0x0A786564
        and (2 of ($pin*) or 2 of ($nsc*))
        and (2 of ($tm*))
        and (1 of ($ssl*))
        and (2 of ($cert*))
}
```

**Match rationale:** Banker recon probes whether target banking apps pin certs before attempting bypass. CertificatePinner + TrustManager + SSLContext + certificate inspection in one package = pinning-aware recon. FP: legitimate security-audit tools — check package context.

**Companion Frida snippet — CertPinnerProbe TLS monitor:**

```javascript
// Inline companion — not a numbered hook. Supplements YARA Rule 20 with runtime detection.
Java.perform(function() {
    // Monitor CertificatePinner.check — catches pinning validation probes
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(hostname, peerCerts) {
            console.log("[CERTPROBE] CertificatePinner.check('" + hostname + "', " +
                peerCerts.size() + " certs)");
            console.log("  [RECON] App probing pinning enforcement for: " + hostname);
            return this.check(hostname, peerCerts);
        };
    } catch(e) {}

    // Monitor X509TrustManager — catches custom trust managers
    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    TrustManagerFactory.getTrustManagers.implementation = function() {
        var tms = this.getTrustManagers();
        console.log("[CERTPROBE] TrustManagerFactory.getTrustManagers() — " + tms.length + " managers");
        for (var i = 0; i < tms.length; i++) {
            console.log("  Manager[" + i + "]: " + tms[i].getClass().getName());
        }
        return tms;
    };

    // Monitor SSLContext.init — catches custom SSL setup
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
        console.log("[CERTPROBE] SSLContext.init() — custom TrustManager injected");
        if (tm !== null) {
            for (var i = 0; i < tm.length; i++) {
                console.log("  TrustManager[" + i + "]: " + tm[i].getClass().getName());
            }
        }
        return this.init(km, tm, sr);
    };
});
```

### YARA Rule 21: RestrictedSettingsBypass Accessibility Enablement

```
rule Takopii_RestrictedSettingsBypass {
    meta:
        description = "Detects Android 13+ Restricted Settings bypass via Accessibility auto-click"
        author = "Takopii Detection Corpus"
        family = "Anatsa / Zombinder"
        mitre = "T1626.001"
        specimen = "stage-1-evasion"

    strings:
        // Restricted Settings UI targets
        $rs1 = "com.android.settings" ascii
        $rs2 = "restricted_setting" ascii
        $rs3 = "MANAGE_UNKNOWN_SOURCES" ascii

        // Accessibility enablement
        $a11y1 = "ENABLED_ACCESSIBILITY_SERVICES" ascii
        $a11y2 = "accessibility_enabled" ascii
        $a11y3 = "Settings.Secure" ascii

        // Package installer intent
        $pkg1 = "ACTION_INSTALL_PACKAGE" ascii
        $pkg2 = "REQUEST_INSTALL_PACKAGES" ascii
        $pkg3 = "canRequestPackageInstalls" ascii

        // Session-based install (Android 14+)
        $sess1 = "PackageInstaller" ascii
        $sess2 = "createSession" ascii
        $sess3 = "openSession" ascii

        // Auto-click dispatch
        $click1 = "performAction" ascii
        $click2 = "ACTION_CLICK" ascii
        $click3 = "findAccessibilityNodeInfosByText" ascii

    condition:
        uint32(0) == 0x0A786564
        and (1 of ($rs*))
        and (2 of ($a11y*))
        and (1 of ($pkg*) or 1 of ($sess*))
        and (2 of ($click*))
}
```

**Match rationale:** Android 13+ restricted settings block sideloaded apps from requesting Accessibility. Banker trojans (Anatsa, Zombinder) bypass by using existing Accessibility to auto-click through Settings UI. Settings-provider writes + accessibility enablement + package installer + auto-click dispatch = bypass fingerprint.

**Companion Frida snippet — RestrictedSettingsBypass monitor:**

```javascript
// Inline companion — not a numbered hook. Supplements YARA Rule 21 with runtime detection.
Java.perform(function() {
    // Monitor Settings.Secure writes — catches accessibility enablement attempts
    var Settings_Secure = Java.use("android.provider.Settings$Secure");
    Settings_Secure.putString.overload('android.content.ContentResolver',
        'java.lang.String', 'java.lang.String')
        .implementation = function(resolver, name, value) {
        if (name === "enabled_accessibility_services" ||
            name === "accessibility_enabled") {
            console.log("[RESTRICT-BYPASS] Settings.Secure.putString('" + name +
                "', '" + value + "')");
            console.log("  [CRITICAL] Accessibility enablement write — restricted settings bypass?");
        }
        return this.putString(resolver, name, value);
    };

    // Monitor performAction on Settings nodes
    var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    AccessibilityNodeInfo.performAction.overload('int')
        .implementation = function(action) {
        var pkg = "";
        try { pkg = this.getPackageName().toString(); } catch(e) {}
        if (pkg === "com.android.settings" && action === 16) {  // ACTION_CLICK = 16
            var text = "";
            try { text = this.getText().toString(); } catch(e) {}
            console.log("[RESTRICT-BYPASS] Auto-click on Settings node: '" + text + "'");
            console.log("  [ALERT] Potential restricted settings bypass via A11y auto-click");
        }
        return this.performAction(action);
    };

    // Monitor PackageInstaller session creation
    var PackageInstaller = Java.use("android.content.pm.PackageInstaller");
    PackageInstaller.createSession.implementation = function(params) {
        console.log("[RESTRICT-BYPASS] PackageInstaller.createSession()");
        console.log("  [ALERT] Session-based sideload install initiated");
        return this.createSession(params);
    };
});
```

### YARA Rule 22: AntiDebug Triple-Layer Detection

```
rule Takopii_AntiDebug_TripleLayer {
    meta:
        description = "Detects 3-layer anti-debug — Java API + /proc/self/status TracerPid + timing delta"
        author = "Takopii Detection Corpus"
        family = "SharkBot / Anatsa / Generic"
        mitre = "T1622"
        specimen = "stage-1-evasion"

    strings:
        // Layer 1: Java debug API
        $java1 = "Debug.isDebuggerConnected" ascii
        $java2 = "isDebuggerConnected" ascii
        $java3 = "Debug.waitingForDebugger" ascii

        // Layer 2: /proc/self/status TracerPid
        $proc1 = "/proc/self/status" ascii
        $proc2 = "TracerPid" ascii
        $proc3 = "/proc/self/maps" ascii

        // Layer 3: Timing-based detection
        $time1 = "nanoTime" ascii
        $time2 = "currentTimeMillis" ascii
        $time3 = "elapsedRealtime" ascii

        // Kill response
        $resp1 = "System.exit" ascii
        $resp2 = "killProcess" ascii
        $resp3 = "finishAffinity" ascii
        $resp4 = "finishAndRemoveTask" ascii

    condition:
        uint32(0) == 0x0A786564
        and (1 of ($java*))
        and (1 of ($proc*))
        and (1 of ($time*))
        and (1 of ($resp*))
}
```

**Match rationale:** Production banker malware runs 3 concurrent debug detection layers. All three in one DEX with kill response = high-confidence anti-analysis. FP: some DRM/RASP SDKs use same pattern — correlate with other banker indicators.

### YARA Rule 23: AntiEmulator Build-Prop Signature Pack

```
rule Takopii_AntiEmulator_BuildProp {
    meta:
        description = "Detects 14-check emulator/sandbox detection via Build properties + sensors + telephony"
        author = "Takopii Detection Corpus"
        family = "SharkBot / ERMAC2 / Generic"
        mitre = "T1633.001"
        specimen = "stage-1-evasion"

    strings:
        // Build property checks (≥5 required)
        $bp1 = "Build.PRODUCT" ascii
        $bp2 = "Build.MODEL" ascii
        $bp3 = "Build.MANUFACTURER" ascii
        $bp4 = "Build.BRAND" ascii
        $bp5 = "Build.DEVICE" ascii
        $bp6 = "Build.HARDWARE" ascii
        $bp7 = "Build.FINGERPRINT" ascii
        $bp8 = "Build.BOARD" ascii

        // Emulator-specific string literals
        $emu1 = "generic" ascii
        $emu2 = "google_sdk" ascii
        $emu3 = "Emulator" ascii
        $emu4 = "Android SDK" ascii
        $emu5 = "Genymotion" ascii
        $emu6 = "goldfish" ascii
        $emu7 = "ranchu" ascii

        // Sensor presence checks
        $sensor1 = "SensorManager" ascii
        $sensor2 = "TYPE_ACCELEROMETER" ascii
        $sensor3 = "TYPE_GYROSCOPE" ascii

        // Telephony service checks
        $tel1 = "TelephonyManager" ascii
        $tel2 = "getSimState" ascii
        $tel3 = "getNetworkOperatorName" ascii

    condition:
        uint32(0) == 0x0A786564
        and (5 of ($bp*))
        and (3 of ($emu*))
        and (1 of ($sensor*))
        and (1 of ($tel*))
}
```

**Match rationale:** SharkBot's anti-emulator battery checks ≥5 Build properties + emulator strings + sensor presence + telephony. Threshold of 5 Build properties distinguishes from legitimate device-info logging (which reads 1-2). 3+ emulator string constants confirms intent.

### YARA Rule 24: AntiFrida 5-Vector Detection Pack

```
rule Takopii_AntiFrida_FiveVector {
    meta:
        description = "Detects 5-vector Frida detection — port + maps + paths + library + named-pipe"
        author = "Takopii Detection Corpus"
        family = "Generic banker evasion"
        mitre = "T1622"
        specimen = "stage-1-evasion"

    strings:
        // Vector 1: Default port scan
        $port1 = "27042" ascii
        $port2 = "27043" ascii

        // Vector 2: /proc/self/maps scanning
        $maps1 = "/proc/self/maps" ascii
        $maps2 = "frida" ascii

        // Vector 3: Known file paths
        $path1 = "/data/local/tmp/frida" ascii
        $path2 = "frida-server" ascii
        $path3 = "frida-agent" ascii
        $path4 = "frida-gadget" ascii

        // Vector 4: Library name scanning
        $lib1 = "frida-agent" ascii
        $lib2 = "libfrida" ascii
        $lib3 = "gmain" ascii

        // Vector 5: Named pipe / D-Bus
        $pipe1 = "linjector" ascii
        $pipe2 = "gum-js-loop" ascii
        $pipe3 = "/tmp/frida-" ascii

    condition:
        uint32(0) == 0x0A786564
        and (1 of ($port*))
        and ($maps1)
        and (1 of ($path*))
        and (1 of ($lib*))
        and (1 of ($pipe*))
}
```

**Match rationale:** Production banker malware runs ≥5 concurrent Frida detection vectors. All five present = comprehensive anti-instrumentation. Vector 5 (named pipe / D-Bus) distinguishes from simple port-check (some security apps do that alone). FP: RASP SDKs embed Frida detection — correlate with other banker indicators.

---

### Sigma Rule 27: CertPinnerProbe TLS Handshake Inspection

```yaml
title: TLS Certificate Inspection from Non-Browser App
id: takopii-certpinner-probe-tls
status: experimental
logsource:
    product: android
    service: network
detection:
    selection_tls_handshake:
        EventType: 'TLSClientHello'
        SourceApp|contains:
            - 'com.cleanmaster'
            - 'com.wifianalyzer'
            - 'com.skyweather'
            - 'com.docreader'
    selection_cert_inspection:
        EventType: 'CertificateChainAccess'
        Action|contains:
            - 'getEncoded'
            - 'getSubjectDN'
            - 'getIssuerDN'
            - 'getPublicKey'
    timeframe: 10s
    condition: selection_tls_handshake | near selection_cert_inspection
falsepositives:
    - Security audit tools that inspect certificate chains programmatically
    - Custom network monitoring apps
level: medium
tags:
    - attack.discovery
    - attack.t1521
```

**Detection logic:** TLS handshake initiation followed by programmatic certificate field extraction within 10s from a non-browser app. Banker recon probes pinning implementations before deploying bypass. Medium severity — requires correlation with other indicators.

### Sigma Rule 28: RestrictedSettingsBypass Accessibility Auto-Click

```yaml
title: Accessibility Auto-Click on Restricted Settings Dialog
id: takopii-restricted-settings-bypass
status: experimental
logsource:
    product: android
    service: accessibility
detection:
    selection_settings_foreground:
        ForegroundPackage: 'com.android.settings'
        EventType: 'TYPE_WINDOW_STATE_CHANGED'
    selection_a11y_autoclick:
        EventType: 'TYPE_VIEW_CLICKED'
        Source|contains:
            - 'AccessibilityService'
            - 'performAction'
        TargetView|contains:
            - 'allow'
            - 'restricted'
            - 'install unknown'
            - 'accessibility service'
            - 'permit'
    timeframe: 5s
    condition: selection_settings_foreground | near selection_a11y_autoclick
falsepositives:
    - Automated UI testing frameworks (verify non-production device)
level: high
tags:
    - attack.defense_evasion
    - attack.t1626.001
description: >
    Detects AccessibilityService dispatching synthetic clicks on Android Settings screens
    related to restricted settings, unknown sources, or accessibility enablement. This is
    the Anatsa/Zombinder bypass for Android 13+ restricted settings enforcement.
```

### Sigma Rule 29: SharkBot DGA Weekly Domain Resolution

```yaml
title: MessageDigest MD5 with Calendar Week Seed — DGA Domain Generation
id: takopii-sharkbot-dga-weekly
status: experimental
logsource:
    product: android
    service: application
detection:
    selection_md5_init:
        MethodCall: 'MessageDigest.getInstance'
        Argument: 'MD5'
    selection_calendar_seed:
        MethodCall|contains:
            - 'Calendar.get'
            - 'WEEK_OF_YEAR'
    selection_tld_array:
        StringLiteral|contains:
            - '.xyz'
            - '.live'
            - '.store'
            - '.top'
            - '.info'
    selection_dns_pattern:
        EventType: 'DNSQuery'
        QueryName|re: '^[a-f0-9]{16}\.(xyz|live|com|store|info|top|net)$'
    timeframe: 30s
    condition: (selection_md5_init and selection_calendar_seed and selection_tld_array) or selection_dns_pattern
falsepositives:
    - MD5 alone is common; Calendar-week seed + TLD rotation array + 16-hex-char DNS query makes this specific
level: high
tags:
    - attack.command_and_control
    - attack.t1568.002
description: >
    Detects SharkBot V2.8 DGA pattern: MD5(TLD + ISO_week + year) → first 16 hex chars → 7
    candidate domains per week across .xyz/.live/.com/.store/.info/.top/.net. Defender can
    precompute all future domains for sinkholing. Also matches DNS query pattern directly.
```

### Sigma Rule 30: Clipper Clipboard Polling from AccessibilityService

```yaml
title: Periodic Clipboard Access from AccessibilityService Context
id: takopii-clipper-a11y-polling
status: experimental
logsource:
    product: android
    service: accessibility
detection:
    selection_clipboard_read:
        MethodCall: 'ClipboardManager.getPrimaryClip'
        CallerContext|contains: 'AccessibilityService'
    selection_frequency:
        EventCount|gte: 3
    timeframe: 10s
    condition: selection_clipboard_read | count() >= 3
falsepositives:
    - Password managers polling clipboard for auto-clear (typically 1x, not periodic)
level: high
tags:
    - attack.collection
    - attack.t1414
description: >
    Detects clipboard polling at clipper-malware cadence (Takopii: 2500ms, wild: 1000-5000ms)
    from AccessibilityService context. Android 10+ restricted background clipboard; modern
    clippers use A11y as Path 2 bypass. ≥3 reads in 10s from A11y = high confidence clipper.
```

### Sigma Rule 31: Reflection Chain Targeting Sensitive API

```yaml
title: Reflective Dispatch to Sensitive Android API via Class.forName Chain
id: takopii-reflection-sensitive-api
status: experimental
logsource:
    product: android
    service: application
detection:
    selection_classforname:
        MethodCall: 'Class.forName'
        Argument|contains:
            - 'android.telephony'
            - 'android.provider.Telephony'
            - 'android.app.admin.DevicePolicyManager'
            - 'android.accessibilityservice'
            - 'android.content.ClipboardManager'
            - 'android.app.NotificationManager'
    selection_getmethod:
        MethodCall|contains:
            - 'getDeclaredMethod'
            - 'getMethod'
    selection_invoke:
        MethodCall: 'Method.invoke'
    timeframe: 5s
    condition: selection_classforname | near selection_getmethod | near selection_invoke
falsepositives:
    - Plugin frameworks (DroidPlugin, VirtualApp) using reflection for component management
    - Some OEM customization layers
level: medium
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1407
description: >
    Detects reflective dispatch chain (Class.forName → getDeclaredMethod → invoke) targeting
    sensitive Android APIs. Banker malware hides direct API calls behind reflection to evade
    static analysis. 3-step chain targeting telephony, accessibility, or clipboard APIs is
    high-signal when correlated with other banker indicators.
```

### Sigma Rule 32: OkHttp POST with Credential Exfiltration Fields

```yaml
title: OkHttp POST Containing Credential or Bot Registration Fields
id: takopii-okhttp-c2-exfil
status: experimental
logsource:
    product: android
    service: network
detection:
    selection_okhttp_post:
        Library: 'okhttp3'
        HttpMethod: 'POST'
    selection_exfil_fields:
        RequestBody|contains:
            - 'bot_id'
            - 'credentials'
            - 'device_id'
            - 'sms_list'
            - 'otp_code'
            - 'keylog'
            - 'screen_text'
            - 'clipboard_data'
    condition: selection_okhttp_post and selection_exfil_fields
falsepositives:
    - Debug builds sending analytics to local servers (field-name overlap is unlikely)
level: critical
tags:
    - attack.exfiltration
    - attack.t1437.001
description: >
    Detects OkHttp POST requests containing credential exfiltration field names (bot_id,
    credentials, sms_list, otp_code, keylog). In lab context, destination is always
    RFC1918/loopback. In wild, remove CIDR filter and match on field names alone.
    Critical — any match is active credential theft.
```

### Sigma Rule 33: SSL Pinning Bypass via Custom TrustManager

```yaml
title: Custom X509TrustManager Override with Permissive Validation
id: takopii-pinning-bypass-detection
status: experimental
logsource:
    product: android
    service: application
detection:
    selection_trustmanager_impl:
        MethodCall|contains:
            - 'X509TrustManager'
            - 'checkServerTrusted'
        ExceptionThrown: false
    selection_sslcontext_init:
        MethodCall: 'SSLContext.init'
        Argument|contains: 'TrustManager'
    selection_empty_return:
        MethodBody|contains: 'return'
        ReturnType: 'void'
    condition: selection_trustmanager_impl and selection_sslcontext_init
falsepositives:
    - Debug builds with intentionally disabled pinning
    - Corporate MDM apps with custom CA trust stores
    - Security testing tools (Frida/Objection pinning bypass — expected in lab)
level: high
tags:
    - attack.credential_access
    - attack.t1557
description: >
    Detects runtime SSL pinning bypass via custom X509TrustManager that accepts all
    certificates (empty checkServerTrusted). Banker malware uses this when not pinning
    its own C2 (ANALYSIS.md §6 asymmetric pinning anti-pattern). High severity from
    unknown app; expected from security testing tools.
```

### Sigma Rule 34: Modular Loader Multi-Stage Fetch-Decode-Load Chain

```yaml
title: Multi-Stage Payload Download Followed by DexClassLoader Instantiation
id: takopii-modular-loader-chain
status: experimental
logsource:
    product: android
    service: application
detection:
    stage1_config_fetch:
        EventType: 'NetworkRequest'
        HttpMethod: 'GET'
        ResponseContentType|contains: 'json'
    stage2_payload_download:
        EventType: 'NetworkRequest'
        HttpMethod: 'GET'
        ResponseSize|gte: 10000
    stage3_file_write:
        EventType: 'FileWrite'
        Path|contains:
            - '/data/data/'
            - '/files/'
            - '/cache/'
        FileExtension|contains:
            - '.dex'
            - '.jar'
            - '.apk'
            - '.bin'
    stage4_dcl_load:
        MethodCall|contains: 'DexClassLoader'
    stage5_cleanup:
        EventType: 'FileDelete'
        Path|contains:
            - '.dex'
            - '.jar'
            - '.apk'
            - '.bin'
    timeframe: 120s
    condition: stage1_config_fetch | near stage2_payload_download | near stage3_file_write | near stage4_dcl_load
falsepositives:
    - Plugin frameworks that download and load code modules (low FP due to full 4-stage chain requirement)
level: critical
tags:
    - attack.execution
    - attack.t1407
description: >
    Detects Anatsa-pattern 4-stage modular loader: config fetch (JSON) → payload download
    (binary ≥10KB) → file write (.dex/.jar/.apk/.bin) → DexClassLoader instantiation.
    Optional stage5 (cleanup/delete) is anti-forensics. Full chain within 120s = high-confidence
    modular loader. Critical — active payload delivery and execution.
```

---

## Dropper-Specific Deep Detection

The dropper (WiFi Analyzer Pro) has the smallest offensive footprint — only delivery logic, no stealer surfaces. Standard banker YARA rules miss it entirely. These rules target the dropper's unique delivery pattern.

### Hook 36: CacheUpdateService Delivery Monitor

```javascript
// Monitor CacheUpdateService — the dropper's entire delivery chain
// Captures: maintenance facade calls, config check, payload download, file write
Java.perform(function() {
    // Monitor ForegroundService start (dropper entry point)
    var Service = Java.use("android.app.Service");
    Service.startForeground.overload('int', 'android.app.Notification')
        .implementation = function(id, notification) {
        var className = this.getClass().getName();
        if (className.indexOf("CacheUpdateService") !== -1 ||
            className.indexOf("wifianalyzer") !== -1) {
            console.log("[DROPPER] CacheUpdateService.startForeground(id=" + id + ")");
            var extras = notification.extras;
            var title = extras.getCharSequence("android.title");
            var text = extras.getCharSequence("android.text");
            console.log("  Notification: " + title + " — " + text);
            console.log("  [ALERT] Dropper FG service started — delivery sequence begins");
        }
        return this.startForeground(id, notification);
    };

    // Monitor getIdentifier — dropper config resolution from resources.arsc
    var Resources = Java.use("android.content.res.Resources");
    Resources.getIdentifier.overload('java.lang.String', 'java.lang.String', 'java.lang.String')
        .implementation = function(name, defType, defPackage) {
        var result = this.getIdentifier(name, defType, defPackage);
        if (defType === "string" && (name.indexOf("config") !== -1 ||
            name.indexOf("header") !== -1 || name.indexOf("cache") !== -1 ||
            name.indexOf("version") !== -1 || name.indexOf("device") !== -1)) {
            console.log("[DROPPER] getIdentifier('" + name + "', '" + defType +
                "', '" + defPackage + "') = " + result);
            console.log("  [CONFIG] Runtime resource ID lookup — C2 config externalized to strings.xml");
        }
        return result;
    };

    // Monitor HttpURLConnection for dropper's two-stage protocol
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        var urlStr = this.toString();
        console.log("[DROPPER] URL.openConnection: " + urlStr);
        if (urlStr.indexOf("/api/v1/check") !== -1) {
            console.log("  [STAGE-1] Config check — C2 activation gate");
        } else if (urlStr.indexOf("/api/v1/payload") !== -1) {
            console.log("  [STAGE-2] Payload download — C2 returned ok:true");
        }
        return this.openConnection();
    };

    // Monitor file write (payload storage)
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        var path = file.getAbsolutePath();
        if (path.indexOf("wifi_db_cache") !== -1 || path.indexOf("cache") !== -1) {
            console.log("[DROPPER] FileOutputStream: " + path);
            console.log("  [PAYLOAD] Payload written as cache file disguise");
        }
        return this.$init(file);
    };

    // Monitor maintenance facade — ScanCacheManager + DatabaseHelper + PerformanceProfiler
    // These fire BEFORE delivery to camouflage the service's real purpose
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.freeMemory.implementation = function() {
        var stack = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
        if (stack.indexOf("PerformanceProfiler") !== -1 ||
            stack.indexOf("CacheUpdateService") !== -1) {
            console.log("[DROPPER] PerformanceProfiler.getMemory() — maintenance facade");
        }
        return this.freeMemory();
    };
});
```

### YARA Rule 17: Dropper getIdentifier Config Pattern

```yara
rule Takopii_Dropper_ResourceConfig {
    meta:
        description = "Detects runtime resource ID lookup for C2 config (getIdentifier pattern)"
        author = "Takopii Framework"
        severity = "medium"
        specimen = "dropper"
        mitre = "T1437"
        note = "Anatsa V4 config externalization — C2 URL in resources.arsc, not DEX"

    strings:
        $getIdentifier = "getIdentifier" ascii
        $string_type = { 00 06 73 74 72 69 6E 67 } // "string" as type arg
        $config_url = "config_url" ascii
        $version_header = "version_header" ascii
        $cache_file = "cache_file" ascii
        $fg_service = "startForeground" ascii
        $http_conn = "HttpURLConnection" ascii
        $write_bytes = "writeBytes" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $getIdentifier and
        ($config_url or $version_header or $cache_file) and
        ($fg_service or $http_conn) and
        $write_bytes
}
```

### Sigma Rule 25: Dropper Two-Stage Check-Then-Download

```yaml
title: ForegroundService Config Check Followed by Binary Download
id: takopii-dropper-two-stage-001
status: experimental
description: |
    Detects dropper two-stage delivery: ForegroundService starts with
    low-priority notification, performs HTTP GET to config endpoint,
    receives JSON activation response, then performs second HTTP GET
    for binary payload. Combined with cache-maintenance API calls
    (ScanCacheManager, DatabaseHelper, PerformanceProfiler) immediately
    before network activity — maintenance facade pattern.
logsource:
    product: android
    category: network
detection:
    fg_start:
        api_call: 'Service.startForeground'
        notification_priority: 'LOW'
    maintenance_calls:
        api_call|contains:
            - 'cache'
            - 'vacuum'
            - 'freeMemory'
    config_check:
        method: 'GET'
        url|contains: '/check'
        response_content_type: 'application/json'
    payload_download:
        method: 'GET'
        response_content_type: 'application/octet-stream'
    timeframe: 30s
    condition: fg_start and config_check and payload_download
level: high
tags:
    - attack.execution
    - attack.t1407
falsepositives:
    - Apps that check server for updates then download binary patches
    - Game apps downloading asset bundles after config check
```

### Sigma Rule 26: Resource ID Lookup for Network Config

```yaml
title: Dynamic Resource Identifier Lookup for Network Configuration
id: takopii-dropper-resource-lookup-001
status: experimental
description: |
    Detects Resources.getIdentifier() calls resolving network-related
    string resources at runtime (config_url, version_header, device_header).
    Runtime lookup avoids compiled R.string references that appear in
    DEX string pool — the config lives only in resources.arsc.
logsource:
    product: android
    category: resource
detection:
    identifier_lookup:
        api_call: 'Resources.getIdentifier'
        name|contains:
            - 'config_url'
            - 'version_header'
            - 'device_header'
            - 'cache_file'
            - 'cache_type'
        type: 'string'
    subsequent_network:
        api_call|contains:
            - 'HttpURLConnection'
            - 'openConnection'
    timeframe: 60s
    condition: identifier_lookup and subsequent_network
level: medium
tags:
    - attack.defense_evasion
    - attack.t1027
```

### Dropper Filesystem Forensics

```bash
# Dropper-specific filesystem detection

# Check for payload file disguised as WiFi cache
adb shell ls -la /data/data/com.wifianalyzer.pro/files/cache/
# Expect: wifi_db_cache.dat — check file type
adb shell file /data/data/com.wifianalyzer.pro/files/cache/wifi_db_cache.dat
# If payload is DEX: "data" or "Dalvik dex file"
# If payload is APK: "Java archive data (JAR)"
# WiFi database would be: "SQLite 3.x database"

# Check notification channel setup (dropper creates "wifi_updates" channel)
adb shell dumpsys notification | grep -A5 "wifi_updates"

# Check foreground service history
adb shell dumpsys activity services com.wifianalyzer.pro

# Verify resources.arsc config — extract without full decompile
aapt dump resources dropper.apk | grep -i "config_url\|version_header\|cache_file"
```

---

## Detection Pipeline Workflow

End-to-end pipeline for processing unknown APKs through the detection corpus. Mirrors the workflow a SOC analyst or mobile threat researcher runs.

### Phase 1: Automated Triage (< 5 minutes)

```bash
# 1. Hash + provenance
sha256sum unknown.apk

# 2. YARA static scan — runs all 24 rules
yara -r scripts/detection/yara/master.yar unknown.apk

# 3. Manifest permission analysis
aapt dump xmltree unknown.apk AndroidManifest.xml | grep -E "permission|service|receiver"

# 4. Component inventory
aapt dump badging unknown.apk | head -40

# 5. Signing cert inspection
apksigner verify --print-certs unknown.apk

# 6. MobSF upload (custom YARA rules mount as volume)
curl -F file=@unknown.apk http://localhost:8000/api/v1/upload \
  -H "Authorization: $MOBSF_KEY"
```

**Output:** Triage card — hash, permissions, component list, YARA hits, suspect-banker score.

### Phase 2: Static Deep Analysis (15-30 minutes)

```bash
# 1. Decompile
jadx -d /tmp/decompiled unknown.apk

# 2. Suspicious class hunt (from ANALYSIS.md §3)
grep -rn "AccessibilityService\|NotificationListenerService" /tmp/decompiled/
grep -rn "DexClassLoader\|InMemoryDexClassLoader" /tmp/decompiled/
grep -rn "getIdentifier.*string" /tmp/decompiled/     # Dropper config pattern
grep -rn "intArrayOf\|arrayOf.*Int" /tmp/decompiled/   # intArrayOf encoding

# 3. Network code audit
grep -rn "OkHttpClient\|HttpURLConnection\|Retrofit" /tmp/decompiled/
grep -rn "CertificatePinner\|hostnameVerifier" /tmp/decompiled/

# 4. Resources.arsc analysis (catches dropper config externalization)
aapt dump resources unknown.apk | grep -iE "url|endpoint|server|host|config"

# 5. Extract IOCs using analyst tooling
python3 scripts/analyst-tools/extract-iocs.py unknown.apk

# 6. Family attribution
python3 scripts/analyst-tools/family-attribution.py unknown.apk
```

**Output:** Package map, suspicious class list, network code inventory, resource-based IOCs, family attribution candidates.

### Phase 3: Dynamic Analysis (30-60 minutes)

```bash
# 1. Install on lab device
adb install unknown.apk

# 2. Attach Frida with master monitor
frida -U -l scripts/detection/frida-monitor/takopii-master-monitor.js -f <package>

# 3. Capture network traffic
mitmproxy --mode transparent --showhost -w capture.flow

# 4. Exercise the app (manual interaction + automated navigation)
# Monitor logcat for telemetry
adb logcat -s "ANTIFRIDA\|ANTIEMU\|ANTIDEBUG\|ENVGATE\|CREDSTORE\|NLS\|SMS\|OVERLAY"

# 5. dumpsys forensics
adb shell dumpsys accessibility | grep -A10 <package>
adb shell dumpsys notification | grep -A10 <package>
adb shell dumpsys jobscheduler | grep <package>
```

**Output:** Frida hook log, network capture, runtime behavior events, Sigma rule matches.

### Phase 4: Correlation + Reporting

```bash
# 1. Run corpus validation against sample
python3 scripts/analyst-tools/corpus-validation.py unknown.apk

# 2. Purple team iteration (if new detection gaps found)
python3 scripts/analyst-tools/purple-iteration.py \
  --sample unknown.apk --corpus scripts/detection/ --gaps detected

# 3. Generate structured report
python3 scripts/analyst-tools/extract-iocs.py unknown.apk --format json > ioc-report.json
```

**Output:** Structured IOC report, detection gap analysis, new rule candidates.

### Tool Integration Reference

| Tool | Integration Point | Rule Format | Automation |
|---|---|---|---|
| MobSF | Custom YARA volume mount | YARA (.yar) | API upload → scan → JSON report |
| Frida | Master monitor script | JavaScript hooks | `frida -U -l master-monitor.js -f <pkg>` |
| SIEM (Splunk/Elastic) | Sigma rules import | Sigma (.yml) | `sigma convert` → SIEM query |
| YARA CLI | Direct scan | YARA (.yar) | `yara -r master.yar *.apk` |
| mitmproxy | Transparent proxy | Network capture | `mitmproxy --mode transparent` |
| logcat | Event stream | Text patterns | `adb logcat -s TAG1\|TAG2` |
| dumpsys | Runtime state query | Text output | `adb shell dumpsys <subsystem>` |

---

## RASP Detection Coverage Analysis

Commercial RASP products wrap the **banking target app** (DVBank). From the blue team's perspective, RASP is one defense layer — not a complete solution.

### What RASP Catches

| Attack Surface | RASP Detection | Detection Mechanism |
|---|---|---|
| Frida attachment to wrapped app | **Yes** | Port scan + /proc/self/maps + library scan |
| Root environment on device | **Yes** | RootBeer-style checks + su binary scan |
| APK tamper (repackaged banking app) | **Yes** | Signature verification + hash check |
| Debugger attachment | **Yes** | Debug.isDebuggerConnected + TracerPid |
| Emulator environment | **Partial** | Build prop checks + sensor presence |
| SSL pinning bypass on wrapped app | **Yes** (self-healing pin) | CertificatePinner re-enforcement |

### What RASP Cannot Catch (Critical Gap)

| Attack Surface | RASP Detection | Why Not |
|---|---|---|
| AccessibilityService reading wrapped app's text | **No** | OS-level service — runs in separate process, RASP has no visibility |
| TYPE_ACCESSIBILITY_OVERLAY (2032) over wrapped app | **No** | Overlay rendered by banker's process, not the wrapped app |
| NotificationListenerService reading wrapped app's push notifications | **No** | NLS operates at system level — reads all notifications regardless |
| SMS BroadcastReceiver intercepting bank-sent OTP | **No** | SMS interception occurs before any app receives the message |
| Clipboard capture from AccessibilityService context | **No** | A11y bypasses Android 10+ clipboard restrictions |
| ATS gesture injection into wrapped app | **No** | dispatchGesture is an OS API — RASP cannot block external gesture dispatch |
| Hidden VNC capturing wrapped app's screen | **No** | MediaProjection captures at compositor level — separate from app process |
| NFC relay forwarding wrapped app's payment APDUs | **No** | NFC relay operates at HostApduService level — different app entirely |

### Defense Layer Stacking

```
LAYER 1 — RASP (in-app):        Protects against direct tampering (Frida, root, repack)
LAYER 2 — MTD (on-device):      Detects cross-app attacks (A11y abuse, overlay, SMS intercept)
LAYER 3 — Server-side fraud:    Detects anomalous transactions (device fingerprint, behavioral biometrics)
LAYER 4 — Detection rules:      Post-incident analysis (YARA/Sigma/Frida rules from this corpus)
```

No single layer is sufficient. RASP without MTD leaves the Accessibility+Overlay attack surface completely undefended. MTD without RASP leaves the banking app vulnerable to direct tampering. Server-side fraud detection catches what both miss (e.g., ATS-driven transfers that pass all client-side checks).

### RASP Bypass Matrix Status

Per ANALYSIS.md §10 — field-test results for public Frida scripts against RASP-wrapped DVBank:

| Vendor | Tier | Test Status |
|---|---|---|
| Talsec FreeRASP | Tier 1 — accessible | Pending field test |
| DoveRunner / AppSealing | Tier 1 — accessible | Pending field test |
| Build38 / OneSpan | Tier 1 — accessible | Pending field test |
| Promon SHIELD | Tier 2 — sales-gated | Vendor contact required |
| GuardSquare DexGuard | Tier 2 — sales-gated | Vendor contact required |
| Verimatrix XTD | Tier 3 — community | Contribution welcome |
| Zimperium zKeyBox | Tier 3 — community | Contribution welcome |

Full matrix: [`../benchmarks/rasp_bypass_matrix.md`](../benchmarks/rasp_bypass_matrix.md). Methodology: [`red-team-rasp-bypass-playbook.md`](red-team-rasp-bypass-playbook.md).

---

## Detection Hierarchy (Recommended Priority)

```
PRIORITY 1 -- Behavioral (survives all evasion):
  |-- ContentResolver SMS query from non-SMS app
  |-- Accessibility -> overlay window creation chain (500ms delay signature)
  |-- ATS kill chain: A11y text capture + gesture injection + OTP drain in 60s window
  |-- dispatchGesture from non-foreground package during banking session
  |-- DexClassLoader instantiation + file deletion within 30s
  |-- Periodic network beacon at 15-min intervals from background
  |-- Batch JSON POST with mixed data types (credential + otp + keystroke)
  |-- Clipboard polling from AccessibilityService context (2500ms cadence)
  +-- NLS + SMS dual OTP capture from same package

PRIORITY 2 -- Manifest (cheap, first-pass triage):
  |-- AccessibilityService + NLS + SMS in same manifest
  |-- FOREGROUND_SERVICE_SPECIAL_USE type
  |-- QUERY_ALL_PACKAGES + SMS permissions
  |-- ContentProvider pre-Application init pattern
  +-- BOOT_COMPLETED + FG service + network in same manifest

PRIORITY 3 -- Static (fragile, per-build):
  |-- DEX string pool patterns (bypassed by externalization)
  |-- Library fingerprints (bypassed by platform API substitution)
  |-- R8 bytecode topology (bypassed by standard ProGuard config)
  +-- intArrayOf encoding (heuristic only, high FP rate alone)
```

Priority 3 is what ML classifiers primarily use. It is the weakest layer. See [`VT-EVASION-RESEARCH.md`](VT-EVASION-RESEARCH.md) for empirical proof.

---

## What VirusTotal Missed (And Why)

All 4 specimens at 0/66 despite:
- Active SMS reading via ContentResolver
- HTTP POST exfiltration to C2
- Foreground service persistence
- Boot receiver restart
- DexClassLoader runtime loading + anti-forensics
- AccessibilityService + overlay rendering
- Full ATS engine — 10-command state machine with automated transfer capability
- 3-path gesture injection (performAction + dispatchGesture + performGlobalAction)
- OTP auto-fill from intercepted SMS/NLS (Stage 3→4 bridge)
- Herodotus-pattern behavior mimicry (300-3000ms jitter)
- 9-capability A11y nerve center (keylogging + screen scraping + clipboard + overlay + ATS)
- Clipboard polling every 2500ms from AccessibilityService context
- NFC relay capability
- Residential proxy capability
- DGA domain generation
- 19-command C2 protocol
- SMS worm spreading capability
- Batch exfiltration with 6 data types

**Root cause:** VT's 75 engines primarily use:
1. Signature matching (no signatures for novel specimens)
2. ML classification on build artifacts (defeated by pipeline changes — see VT-EVASION-RESEARCH.md)
3. Heuristic permission analysis (insufficient alone)

**What VT does NOT do:**
- Dynamic execution with SMS provider populated
- ContentResolver call-chain analysis
- Behavioral sequencing (config check -> download -> DCL load -> delete)
- Cross-component correlation (A11y event -> overlay creation)
- ATS state machine detection (command queue + gesture injection + OTP drain)
- dispatchGesture call-chain analysis during banking app sessions
- AccessibilityService event volume analysis (keylogging + screen scraping pattern)
- Clipboard polling cadence detection (2500ms periodic from A11y context)
- Cross-stage bridge analysis (NLS/SMS OTP capture → CredentialStore → ATS auto-fill)
- intArrayOf decode + string reconstruction
- Resource.arsc string analysis correlated with DEX behavior
- DGA algorithm detection (MessageDigest + Calendar is ubiquitous)
- Batch exfil payload structure analysis
- Herodotus timing jitter analysis (uniform distribution = non-human)

---

## Master Rule Index — All 95 Detection Rules

Complete index of the 24 YARA + 34 Sigma + 37 Frida rules in this corpus. Rules are grouped by format, numbered sequentially, and cross-referenced to the specimen(s) each primarily targets.

### YARA Rules (24) — Static Analysis

| # | Rule Name | Primary Target | Section |
|---|---|---|---|
| 1 | `Takopii_SMS_ContentResolver_Pattern` | sms-stealer | Core Specimens |
| 2 | `Takopii_SMS_ContentResolver_Pattern_NoModule` | sms-stealer (variant) | Core Specimens |
| 3 | `Takopii_Dropper_Config_Download` | dropper | Core Specimens |
| 4 | `Takopii_Overlay_Banker_Shape` | overlay-banker | Core Specimens |
| 5 | `Takopii_DGA_MD5_Calendar` | stage-1-evasion | Core Specimens |
| 6 | `Takopii_Resource_SMS_Stealer` | sms-stealer | Core Specimens |
| 7 | `Takopii_DCL_AntiForensics` | stage-1-evasion | Core Specimens |
| 7b | `Takopii_IntArray_String_Encoding` | stage-1-evasion | Core Specimens |
| 8 | `Takopii_A11y_Overlay_2032` | stage-1-evasion | Frontier 2025-2026 |
| 9 | `Takopii_HiddenVnc_MediaProjection` | stage-1-evasion | Frontier 2025-2026 |
| 10 | `Takopii_NfcRelay_GhostTap` | stage-1-evasion | Frontier 2025-2026 |
| 11 | `Takopii_ResidentialProxy_SOCKS5` | stage-1-evasion | Frontier 2025-2026 |
| 12 | `Takopii_SsoHijacker_MFA_AutoApprove` | stage-1-evasion | Frontier 2025-2026 |
| 13 | `Takopii_YamuxProxy_Multiplexer` | stage-1-evasion | Frontier 2025-2026 |
| 14 | `Takopii_EarlyInitProvider_NoOp` | stage-1-evasion | Composition |
| 15 | `Takopii_SmsWorm_Spreading` | stage-1-evasion | Composition |
| 16 | `ScreenReader_ATS_TreeTraversal` | stage-1-evasion | Composition |
| 17 | `Takopii_Dropper_ResourceConfig` | dropper | Dropper-Specific |
| 18 | `Takopii_BehaviorMimicry_Jitter` | stage-1-evasion | Corpus Completion |
| 19 | `Takopii_TeeOffload_KeyStore` | stage-1-evasion | Corpus Completion |
| 20 | `Takopii_CertPinnerProbe` | stage-1-evasion | Corpus Completion |
| 21 | `Takopii_RestrictedSettingsBypass` | stage-1-evasion | Corpus Completion |
| 22 | `Takopii_AntiDebug_TripleLayer` | stage-1-evasion | Corpus Completion |
| 23 | `Takopii_AntiEmulator_BuildProp` | stage-1-evasion | Corpus Completion |
| 24 | `Takopii_AntiFrida_FiveVector` | stage-1-evasion | Corpus Completion |

### Sigma Rules (34) — Runtime Behavioral

| # | Rule ID | Primary Target | Section |
|---|---|---|---|
| 1 | `takopii-sms-contentresolver-access` | sms-stealer | Core Specimens |
| 2 | `takopii-fgservice-config-download` | dropper, stage-1 | Core Specimens |
| 3 | `takopii-a11y-overlay-creation` | overlay-banker | Core Specimens |
| 4 | `takopii-dcl-load-delete` | stage-1-evasion | Core Specimens |
| 5 | `takopii-workmanager-beacon` | stage-1-evasion | Core Specimens |
| 6 | `takopii-nls-sms-same-package` | overlay-banker | Core Specimens |
| 7 | `takopii-ats-killchain-gesture` | overlay-banker, stage-1 | Core Specimens |
| 8 | `takopii-a11y-foreground-overlay-pipeline` | overlay-banker | Core Specimens |
| 9 | `takopii-multiaxis-sensor-flat` | stage-1-evasion | Frontier 2025-2026 |
| 10 | `takopii-a11y-overlay-2032-timing` | stage-1-evasion | Frontier 2025-2026 |
| 11 | `takopii-hiddenvnc-frame-capture` | stage-1-evasion | Frontier 2025-2026 |
| 12 | `takopii-nfcrelay-apdu-network` | stage-1-evasion | Frontier 2025-2026 |
| 13 | `takopii-residentialproxy-socks5` | stage-1-evasion | Frontier 2025-2026 |
| 14 | `takopii-ssohijacker-autoapprove` | stage-1-evasion | Frontier 2025-2026 |
| 15 | `takopii-teeoffload-key-encrypt-net` | stage-1-evasion | Frontier 2025-2026 |
| 16 | `takopii-perbuild-obfuscation-seed` | stage-1-evasion | Frontier 2025-2026 |
| 17 | `takopii-playintegrity-probe-recon` | stage-1-evasion | Frontier 2025-2026 |
| 18 | `takopii-mediaprojection-autoconsent` | stage-1-evasion | Frontier 2025-2026 |
| 19 | `takopii-noteapp-bip39-scraper` | stage-1-evasion | Frontier 2025-2026 |
| 20 | `takopii-earlyinit-preapp` | stage-1-evasion | Composition |
| 21 | `takopii-stealth-fgservice` | stage-1-evasion | Composition |
| 22 | `takopii-bootreceiver-persistence` | stage-1-evasion | Composition |
| 23 | `takopii-contact-harvester-exfil` | stage-1-evasion | Composition |
| 24 | `takopii-screenreader-tree-traversal` | stage-1-evasion | Composition |
| 25 | `takopii-dropper-check-download` | dropper | Dropper-Specific |
| 26 | `takopii-resource-id-network-config` | dropper | Dropper-Specific |
| 27 | `takopii-certpinner-probe-tls` | stage-1-evasion | Corpus Completion |
| 28 | `takopii-restricted-settings-bypass` | stage-1-evasion | Corpus Completion |
| 29 | `takopii-sharkbot-dga-weekly` | stage-1-evasion | Corpus Completion |
| 30 | `takopii-clipper-a11y-polling` | stage-1-evasion | Corpus Completion |
| 31 | `takopii-reflection-sensitive-api` | stage-1-evasion | Corpus Completion |
| 32 | `takopii-okhttp-c2-exfil` | overlay-banker | Corpus Completion |
| 33 | `takopii-pinning-bypass-detection` | cross-specimen | Corpus Completion |
| 34 | `takopii-modular-loader-chain` | stage-1-evasion | Corpus Completion |

### Frida Hooks (37) — Dynamic Instrumentation

| # | Hook Name | Primary Target | Section |
|---|---|---|---|
| 1 | ContentResolver SMS Monitor | sms-stealer | Core Specimens |
| 2 | HttpURLConnection POST Monitor | sms-stealer, dropper | Core Specimens |
| 3 | WindowManager Overlay Monitor | overlay-banker | Core Specimens |
| 4 | DexClassLoader Monitor | stage-1-evasion | Core Specimens |
| 5 | NotificationListenerService OTP Monitor | overlay-banker | Core Specimens |
| 6 | DGA / MessageDigest Monitor | stage-1-evasion | Core Specimens |
| 7 | OkHttp Exfil Monitor | overlay-banker | Core Specimens |
| 8 | BankerA11yService Event Dispatch Monitor | overlay-banker | Core Specimens |
| 9 | dispatchGesture ATS Monitor | overlay-banker, stage-1 | Core Specimens |
| 10 | Clipboard Polling Monitor | stage-1-evasion | Core Specimens |
| 11 | AntiDebug 3-Layer Defeat | stage-1-evasion | Evasion Bypass |
| 12 | AntiEmulator 14-Check Defeat | stage-1-evasion | Evasion Bypass |
| 13 | AntiFrida 5-Vector Defeat | stage-1-evasion | Evasion Bypass |
| 14 | EnvironmentGate Aggregate Monitor | stage-1-evasion | Evasion Bypass |
| 15 | NativeProtect JNI Monitor | stage-1-evasion | Evasion Bypass |
| 16 | ReflectionHider Interception | stage-1-evasion | Evasion Bypass |
| 17 | StringDecoder XOR + AES Interception | stage-1-evasion | Evasion Bypass |
| 18 | A11yOverlay2032 Intercept | stage-1-evasion | Frontier 2025-2026 |
| 19 | HiddenVnc Frame Rate Monitor | stage-1-evasion | Frontier 2025-2026 |
| 20 | NfcRelay APDU Monitor | stage-1-evasion | Frontier 2025-2026 |
| 21 | ResidentialProxy Session Monitor | stage-1-evasion | Frontier 2025-2026 |
| 22 | BehaviorMimicry Timing Analysis | stage-1-evasion | Frontier 2025-2026 |
| 23 | SsoHijacker Intercept | stage-1-evasion | Frontier 2025-2026 |
| 24 | TeeOffload Key + Crypto Monitor | stage-1-evasion | Frontier 2025-2026 |
| 25 | YamuxProxy Stream Monitor | stage-1-evasion | Frontier 2025-2026 |
| 26 | PerBuildObfuscation Seed Capture | stage-1-evasion | Frontier 2025-2026 |
| 27 | EarlyInitProvider Execution Order | stage-1-evasion | Composition |
| 28 | ContactHarvester Monitor | stage-1-evasion | Composition |
| 29 | SmsWorm Rate-Limited Spread | stage-1-evasion | Composition |
| 30 | AccessibilityEngine Gate Monitor | overlay-banker, stage-1 | Composition |
| 31 | CredentialStore Buffer Monitor | overlay-banker | Composition |
| 32 | NotificationEngine 5-Point Extraction | overlay-banker | Composition |
| 33 | SmsInterceptor Priority Monitor | overlay-banker | Composition |
| 34 | OtpExtractor Confidence Scoring | overlay-banker | Composition |
| 35 | UpdateChannel Response Capture | overlay-banker, stage-1 | Network |
| 35b | ScreenReader A11y Tree Traversal | stage-1-evasion | Composition |
| 36 | CacheUpdateService Delivery Monitor | dropper | Dropper-Specific |

### Corpus Coverage Summary

```
                        sms-stealer    dropper    overlay-banker    stage-1-evasion
YARA rules firing:           3            3             2                19
Sigma rules firing:          2            4             5                27
Frida hooks active:          3            3            10                28
──────────────────────────────────────────────────────────────────────────────────
Total per specimen:          8           10            17                74
```

```
Detection layer coverage:
  Static (YARA):        24 rules — APK-at-rest analysis, no execution needed
  Behavioral (Sigma):   34 rules — runtime event correlation, highest fidelity
  Dynamic (Frida):      37 hooks — real-time API-call-level instrumentation
  ─────────────────────────────────────────────────────────────────────────
  Total:                95 rules — 0 gaps remaining
```

---

## Standalone Detection Rule Files

The inline rules in this document are consolidated into standalone files for integration with detection pipelines:

### Top-Level `detection/` Directory

| Format | File | Inline Rule(s) Covered |
|---|---|---|
| YARA | `detection/yara/sms-stealer.yar` | Rules 1, 2, 6 |
| YARA | `detection/yara/dropper.yar` | Rules 3, 17 |
| YARA | `detection/yara/banker-shape.yar` | Rules 4, 14, 15, 16 |
| YARA | `detection/yara/dga.yar` | Rule 5 |
| YARA | `detection/yara/dcl-antiforensics.yar` | Rule 7 |
| YARA | `detection/yara/intarray-encoding.yar` | Rule 7b |
| YARA | `detection/yara/resource-sms.yar` | Rule 6 (resources.arsc variant) |
| YARA | `detection/yara/frontier.yar` | Rules 8-13 |
| YARA | `detection/yara/rat-capabilities.yar` | Rules 18-24 (advanced capability detection) |
| YARA | `detection/yara/master.yar` | All YARA rules combined |
| Sigma | `detection/sigma/sms-contentresolver.yml` | Rules 1, 5 |
| Sigma | `detection/sigma/dropper-download.yml` | Rules 2, 25, 26 |
| Sigma | `detection/sigma/overlay-trigger.yml` | Rules 3, 8, 10, 28 |
| Sigma | `detection/sigma/dcl-antiforensics.yml` | Rule 4 |
| Sigma | `detection/sigma/workmanager-beacon.yml` | Rules 9, 11 |
| Sigma | `detection/sigma/dual-otp-capture.yml` | Rule 6 |
| Sigma | `detection/sigma/ats-killchain.yml` | Rule 7 |
| Sigma | `detection/sigma/a11y-overlay-chain.yml` | Rules 3, 10 |
| Sigma | `detection/sigma/frontier.yml` | Rules 12-17 |
| Sigma | `detection/sigma/rat-behavioral.yml` | Rules 27-34 (advanced behavioral) |
| Sigma | `detection/sigma/master.yml` | All Sigma rules combined |
| Frida | `detection/frida/sms-monitor.js` | Hooks 1-2 |
| Frida | `detection/frida/overlay-monitor.js` | Hooks 3, 8, 18 |
| Frida | `detection/frida/dcl-monitor.js` | Hook 4 |
| Frida | `detection/frida/nls-monitor.js` | Hook 5 |
| Frida | `detection/frida/dga-monitor.js` | Hook 6 |
| Frida | `detection/frida/a11y-monitor.js` | Hooks 7, 9, 17 |
| Frida | `detection/frida/network-monitor.js` | Hook 10 |
| Frida | `detection/frida/evasion-bypass.js` | Hooks 11-13 |
| Frida | `detection/frida/ats-monitor.js` | Hooks 14-16 |
| Frida | `detection/frida/clipboard-monitor.js` | Hook 19 |
| Frida | `detection/frida/frontier-monitor.js` | Hooks 20-31 |
| Frida | `detection/frida/rat-monitor.js` | Hooks 32-37 |
| Frida | `detection/frida/master-monitor.js` | All Frida hooks combined |

### Stage-1-Evasion Specimen-Specific Detection

The capstone specimen ships its own detection corpus at `specimens/stage-1-evasion/scripts/detection/`:

**YARA (7 rules + master.yar):**
`skyweather-banker-shape.yar`, `anatsa-c2-protocol.yar`, `sms-otp-stealing.yar`, `dcl-reflection-chain.yar`, `dga-domain-rotation.yar`, `credential-exfil-taxonomy.yar`, `ats-gesture-injection.yar`

**Sigma (12 rules + master.yml):**
`skyweather-anatsa-killchain.yml`, `skyweather-workmanager-c2-poll.yml`, `skyweather-dcl-anti-forensics.yml`, `skyweather-overlay-credential-capture.yml`, `skyweather-nls-otp-intercept.yml`, `skyweather-sms-otp-exfil.yml`, `skyweather-permission-escalation.yml`, `skyweather-ats-form-fill.yml`, `skyweather-ats-otp-autofill.yml`, `skyweather-accessibility-abuse.yml`, `skyweather-modular-loader.yml`, `skyweather-update-channel.yml`

**Frida (3 scripts):**
`skyweather-monitor.js` (main observer), `credential-watcher.js` (credential-flow tracker), `ats-watcher.js` (ATS gesture injection monitor)

These are specimen-specific variants tuned to SkyWeather's exact class names and runtime behavior. Use the top-level `detection/` rules for generic banker detection; use stage-1-evasion's scripts for precise SkyWeather analysis.

---

## References

- [`VT-EVASION-RESEARCH.md`](VT-EVASION-RESEARCH.md) — Full 11-round evasion methodology
- [`REDTEAM-ANALYSIS.md`](REDTEAM-ANALYSIS.md) — Offensive technique catalog with source code + detection rule firing matrix
- [`../ANALYSIS.md`](../ANALYSIS.md) §9 — Detection engineering hub
- [`../ANALYSIS.md`](../ANALYSIS.md) §10 — RASP bypass matrix methodology
- [`../techniques/detection/`](../techniques/detection/) — Per-primitive detection spokes
- [`../benchmarks/rasp_bypass_matrix.md`](../benchmarks/rasp_bypass_matrix.md) — RASP field-test results
- [`../scripts/analyst-tools/`](../scripts/analyst-tools/) — Runnable analyst tooling (8 tools)
- [`red-team-rasp-bypass-playbook.md`](red-team-rasp-bypass-playbook.md) — RASP test methodology
- MITRE ATT&CK Mobile: T1407, T1417.002, T1437, T1517, T1582, T1626
