/*
 * YARA rules for SkyWeather evasion specimen detection.
 *
 * These rules catch the specific patterns used in the Stage 1-3
 * evasion specimen. They demonstrate how defenders write static
 * detection for each evasion stage's Android translation.
 *
 * Run: yara -r skyweather-evasion.yar <decompiled-apk-dir>
 *      yara skyweather-evasion.yar classes.dex
 */

rule SkyWeather_ArithmeticStringEncoding
{
    meta:
        description = "Detects arithmetic offset string encoding (Takopii Stage 11)"
        author = "Takopii Detection Engineering"
        reference = "ANALYSIS.md §7, techniques/evasion/string-obfuscation-routines.md"
        mitre = "T1027 - Obfuscated Files or Information"
        severity = "medium"
        false_positive = "Apps using integer arrays for font rendering or pixel data"

    strings:
        // Pattern: intArrayOf followed by values in the 58-135 range
        // (printable ASCII 45-122 shifted by +13)
        // The decode function: (encoded[i] - SHIFT).toChar()
        $decode_loop = "SHIFT" ascii
        $int_array_1 = "intArrayOf" ascii
        $char_array = "CharArray" ascii
        $to_char = "toChar" ascii

        // Specific encoded endpoint pattern (http:// shifted by +13)
        // 'h'=104+13=117, 't'=116+13=129, 'p'=112+13=125
        $encoded_http = { 75 00 81 00 81 00 7D 00 }  // 117,129,129,125 as shorts

    condition:
        $decode_loop and $int_array_1 and $char_array and $to_char
}

rule SkyWeather_HardwareMetricAntiSandbox
{
    meta:
        description = "Detects hardware-metric anti-sandbox checks (Takopii Stage 10)"
        author = "Takopii Detection Engineering"
        reference = "ANALYSIS.md §7, techniques/evasion/anti-emulator-checks.md"
        mitre = "T1497.001 - Virtualization/Sandbox Evasion: System Checks"
        severity = "medium"
        false_positive = "Legitimate apps checking sensor availability for features"

    strings:
        $accel = "TYPE_ACCELEROMETER" ascii
        $gyro = "TYPE_GYROSCOPE" ascii
        $battery = "BATTERY_PROPERTY_CAPACITY" ascii
        $camera = "getCameraIdList" ascii
        $sim = "SIM_STATE_READY" ascii
        $sensor_mgr = "SENSOR_SERVICE" ascii

    condition:
        4 of them
}

rule SkyWeather_AntiDebugTriad
{
    meta:
        description = "Detects Java+Native+Timing anti-debug triad (Takopii Stage 7)"
        author = "Takopii Detection Engineering"
        reference = "ANALYSIS.md §7, techniques/evasion/anti-debug-checks.md"
        mitre = "T1622 - Debugger Evasion"
        severity = "medium"
        false_positive = "Apps with legitimate anti-tampering (banking apps, DRM)"

    strings:
        $java_debug = "isDebuggerConnected" ascii
        $proc_status = "/proc/self/status" ascii
        $tracer_pid = "TracerPid" ascii
        $nano_time = "nanoTime" ascii

    condition:
        $java_debug and ($proc_status or $tracer_pid) and $nano_time
}

rule SkyWeather_DexClassLoaderChain
{
    meta:
        description = "Detects DexClassLoader + reflection payload load chain (Takopii Stage 9)"
        author = "Takopii Detection Engineering"
        reference = "ANALYSIS.md §5, techniques/android-runtime/dexclassloader-runtime-loading.md"
        mitre = "T1398 - Boot or Logon Initialization Scripts"
        severity = "high"
        false_positive = "Apps with legitimate plugin/hot-fix architecture"

    strings:
        $dcl = "DexClassLoader" ascii
        $load_class = "loadClass" ascii
        $get_method = "getMethod" ascii
        $invoke = ".invoke(" ascii
        $new_instance = "newInstance" ascii
        $class_for_name = "Class.forName" ascii

        // Anti-forensics: file deletion after load
        $delete = ".delete()" ascii
        $set_readonly = "setReadOnly" ascii

    condition:
        $dcl and $load_class and ($get_method or $class_for_name) and
        ($invoke or $new_instance) and
        ($delete or $set_readonly)
}

rule SkyWeather_DGAPattern
{
    meta:
        description = "Detects MD5-seeded DGA domain generation (SharkBot-style)"
        author = "Takopii Detection Engineering"
        reference = "ANALYSIS.md §6, techniques/network/dga-domain-rotation.md"
        mitre = "T1568.002 - Dynamic Resolution: Domain Generation Algorithms"
        severity = "high"
        false_positive = "Apps using MD5 for content hashing combined with Calendar"

    strings:
        $md5 = "MessageDigest" ascii
        $md5_algo = "MD5" ascii
        $calendar = "WEEK_OF_YEAR" ascii
        $hex_format = "%02x" ascii
        $url_construct = "http://" ascii

    condition:
        $md5 and $md5_algo and $calendar and $hex_format
}

rule SkyWeather_XorPayloadDecryption
{
    meta:
        description = "Detects XOR rotating-key payload decryption (Takopii Stage 3)"
        author = "Takopii Detection Engineering"
        reference = "ANALYSIS.md §7, techniques/evasion/string-obfuscation-routines.md"
        mitre = "T1140 - Deobfuscate/Decode Files or Information"
        severity = "medium"
        false_positive = "Apps with legitimate XOR-based data processing"

    strings:
        // XOR decrypt pattern: encrypted[i] xor key[i % key.size]
        $xor_op = "xor" ascii
        $modulo = "% key" ascii
        $dex_magic_check_d = { 64 }  // 'd' = 0x64
        $dex_magic_check_e = { 65 }  // 'e' = 0x65
        $dex_magic_check_x = { 78 }  // 'x' = 0x78

        // File write + delete pattern (anti-forensics)
        $cache_name = ".cache_data" ascii
        $update_name = ".update_cache" ascii

    condition:
        $xor_op and ($cache_name or $update_name)
}

rule SkyWeather_BankerShapeComposite
{
    meta:
        description = "Composite rule: full evasion specimen shape detection"
        author = "Takopii Detection Engineering"
        reference = "ANALYSIS.md §2-§7"
        mitre = "T1398, T1027, T1497.001, T1568.002"
        severity = "critical"
        false_positive = "Very low — requires 4+ independent banker indicators"

    strings:
        // Stage 11: encoded strings
        $encoded_strings = "intArrayOf" ascii
        $decode = "SHIFT" ascii

        // Stage 9: DexClassLoader chain
        $dcl = "DexClassLoader" ascii

        // Stage 10: hardware anti-sandbox
        $sensor_check = "TYPE_ACCELEROMETER" ascii

        // Stage 7: anti-debug
        $debug_check = "isDebuggerConnected" ascii

        // Stage 6: DGA
        $dga = "WEEK_OF_YEAR" ascii

        // Stage 3: XOR decrypt
        $xor = "xor" ascii

        // WorkManager beacon
        $work = "OneTimeWorkRequestBuilder" ascii

    condition:
        4 of them
}
