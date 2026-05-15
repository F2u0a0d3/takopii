/*
 * SkyWeather Forecast — Anatsa-Shape C2 Protocol Detection
 *
 * Targets the 4-stage modular loader C2 protocol:
 *   Stage 1: Beacon to /api/v1/beacon with device fingerprint
 *   Stage 2: Config fetch with target_list, ats_commands, kill switch
 *   Stage 3: Payload download -> XOR decrypt -> DexClassLoader
 *   Stage 4: Update channel polling
 *
 * Fires on release DEX: all protocol strings survive R8 (runtime-needed).
 *
 * References:
 *   MITRE ATT&CK Mobile: T1437.001 (Web Protocols), T1398 (Boot/Logon Init)
 *   MASTG: MASTG-CTRL-0013
 *   Family: Anatsa 4-stage architecture (research/02)
 *
 * False positives:
 *   Weather APIs with /api/v1/ prefix — mitigated by AND with ats_commands
 *   or kill switch strings. No legit weather app has these.
 */

rule SkyWeather_C2_Protocol
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "Anatsa-shape C2 beacon + config + payload protocol"
        family      = "SkyWeather"
        mitre       = "T1437.001, T1398"
        mastg       = "MASTG-CTRL-0013"
        severity    = "critical"
        fp_rate     = "very low — beacon + C2 config regex combo"

    strings:
        // C2 endpoint paths (survived R8 — runtime string constants)
        $ep_beacon   = "api/v1/beacon"

        // Payload delivery
        $payload_cache = "update_cache.dex"

        // C2 config parsing regexes (exact strings from DEX)
        $rx_ats      = "\"ats_commands\""
        $rx_kill     = "\"kill\":true"
        $rx_payload  = "\"payload_url\""
        $rx_target   = "\"target_list\""
        $rx_delay    = "delay_ms"

        // Credential exfil JSON shape (serialization format fields)
        $json_evt    = ",\"e\":" // event type field
        $json_txt    = ",\"x\":" // captured text field

    condition:
        uint32(0) == 0x0A786564 and
        $ep_beacon and
        (
            // Full protocol: beacon + config parsing
            (2 of ($rx_*)) or
            // Loader shape: beacon + payload cache
            ($payload_cache) or
            // Exfil shape: beacon + credential JSON
            ($json_evt and $json_txt)
        )
}


rule SkyWeather_Config_Regex_Pack
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "C2 config parsing regex pack — high-signal static indicator"
        family      = "SkyWeather"
        mitre       = "T1437.001"
        severity    = "high"
        fp_rate     = "very low — regex patterns specific to banker C2 config"

    strings:
        // These strings are unique to banker C2 config parsing.
        // No legitimate app embeds strings for ats_commands + kill switch.
        $rx_ats      = "ats_commands"
        $rx_kill     = "\"kill\":true"
        $rx_target   = "target_list"
        $rx_payload  = "payload_url"
        $rx_delay    = "delay_ms"

    condition:
        uint32(0) == 0x0A786564 and
        3 of them
}
