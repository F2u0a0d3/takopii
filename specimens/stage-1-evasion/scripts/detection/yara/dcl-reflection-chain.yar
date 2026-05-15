/*
 * SkyWeather Forecast — DexClassLoader + Payload Chain Detection
 *
 * Targets the modular loader pattern:
 *   C2 fetch -> XOR decrypt -> write update_cache.dex -> DexClassLoader ->
 *   reflective dispatch -> delete file (anti-forensics)
 *
 * R8 survival: DexClassLoader is a framework class (descriptor survives).
 * "update_cache.dex" is a runtime filename constant (survives).
 * Beacon path survives (network constant).
 *
 * References:
 *   MITRE ATT&CK Mobile: T1398 (Boot/Logon), T1407 (Download New Code)
 *   MASTG: MASTG-CTRL-0003
 *   Family: Anatsa 4-stage loader (research/02)
 *
 * False positives:
 *   DexClassLoader alone hits many plugin frameworks (Tencent Tinker,
 *   Google Play Core). Mitigated by requiring update_cache.dex filename
 *   or C2 beacon endpoint — plugin frameworks don't beacon.
 */

rule SkyWeather_DCL_Payload_Chain
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "DexClassLoader modular loader + C2 payload delivery"
        family      = "SkyWeather"
        mitre       = "T1398, T1407"
        mastg       = "MASTG-CTRL-0003"
        severity    = "critical"
        fp_rate     = "low — cache filename + beacon combo eliminates plugin frameworks"

    strings:
        // DexClassLoader framework reference (always survives R8)
        $dcl_class   = "DexClassLoader"
        $dcl_desc    = "Ldalvik/system/DexClassLoader;"

        // InMemoryDexClassLoader (API 26+, alternative loader)
        $imdcl       = "InMemoryDexClassLoader"

        // Payload cache filename (specimen-specific runtime constant)
        $cache_file  = "update_cache.dex"

        // C2 beacon (loader fetches payload after successful beacon)
        $beacon      = "api/v1/beacon"

        // Reflection chain indicators (may survive R8 as framework refs)
        $refl_cfn    = "Class.forName"
        $refl_gdm    = "getDeclaredMethod"
        $refl_invoke = ".invoke("

    condition:
        uint32(0) == 0x0A786564 and
        (
            // Core loader chain: DCL + payload cache file
            (1 of ($dcl_*) and $cache_file) or
            // Full modular loader: DCL + beacon + cache
            (1 of ($dcl_*) and $beacon) or
            // Reflection-heavy loader: DCL + reflection triad (debug builds)
            (1 of ($dcl_*) and 2 of ($refl_*)) or
            // IMDCL variant (newer Android API path)
            ($imdcl and ($cache_file or $beacon))
        )
}
