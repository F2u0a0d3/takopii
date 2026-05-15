# SkyWeather Forecast — Frida Observer Scripts

Dynamic instrumentation scripts for real-time specimen observation.

## Scripts

| Script | Modules | Use Case |
|---|---|---|
| `skyweather-monitor.js` | 14 | Full kill chain — all surfaces, color-coded severity |
| `credential-watcher.js` | 3 | Credential flow only — capture → drain → exfil |
| `ats-watcher.js` | 4 | ATS only — command load → target → gesture → result |

## Usage

```bash
# Prerequisites: frida-server on device, app installed
frida -U com.skyweather.forecast -l skyweather-monitor.js

# Focused watchers (less noise)
frida -U com.skyweather.forecast -l credential-watcher.js
frida -U com.skyweather.forecast -l ats-watcher.js
```

## Master Monitor Modules (14)

| # | Module | Hooks | Severity |
|---|---|---|---|
| 1 | AccessibilityEngine | onAccessibilityEvent, onServiceConnected | CRITICAL |
| 2 | OverlayRenderer | WindowManager.addView (TYPE=2032 detection) | CRITICAL |
| 3 | NotificationEngine | onNotificationPosted, onListenerConnected | HIGH |
| 4 | SmsInterceptor | BroadcastReceiver.onReceive | HIGH |
| 5 | OtpExtractor | extract, extractAll | HIGH |
| 6 | CredentialStore | capture, drain, toJsonPayload | CRITICAL |
| 7 | SyncTask | doWork (WorkManager beacon) | HIGH |
| 8 | DexClassLoader | constructor, loadClass | CRITICAL |
| 9 | DGA Detection | MessageDigest.getInstance("MD5"), digest | MEDIUM |
| 10 | Reflection | Class.forName (filtered to sensitive APIs) | MEDIUM |
| 11 | Network | HttpURLConnection output/response | HIGH |
| 12 | ATS Engine | onTargetForegrounded, loadCommands | CRITICAL |
| 13 | Gesture Injection | dispatchGesture, performGlobalAction, SET_TEXT | CRITICAL |
| 14 | Anti-Forensics | File.delete on app-private paths | MEDIUM |

## Pattern Detection

Master monitor counts A11y events per 60-second window. At 50+ events:

```
[CRITICAL] BANKER ALERT: 73 accessibility events in 60s — abnormal volume
```

## Color Coding

```
Red     (91m)  — CRITICAL: credential capture, overlay, ATS trigger
Yellow  (93m)  — HIGH: OTP extraction, SMS intercept, NLS
Cyan    (96m)  — MEDIUM: DGA, reflection, network
Magenta (95m)  — ATS command queue
White          — INFO: service connect, low-severity events
```
