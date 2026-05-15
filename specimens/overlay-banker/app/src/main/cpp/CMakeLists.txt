cmake_minimum_required(VERSION 3.22.1)
project("docreader_native")

# Native protection module — Klopatra Virbox / Albiriox ARMv8 VM pattern.
#
# Real banker uses native code for:
#   1. String decryption in C (harder to decompile than Kotlin/Java)
#   2. Anti-tamper checks (CRC of DEX, .so integrity)
#   3. Anti-Frida native-level detection (inline hooks, PLT patching)
#   4. Key material storage (C struct, not Java heap — GC won't expose)
#   5. Yamux framing (high-performance TCP multiplexing)
#
# jadx only decompiles DEX. Native code requires IDA/Ghidra/Binary Ninja.
# Most automated scanners skip .so analysis entirely.

add_library(
    docreader_native
    SHARED
    native_protect.cpp
)

target_link_libraries(
    docreader_native
    android
    log
)
