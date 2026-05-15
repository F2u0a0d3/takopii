/*
 * SkyWeather Forecast — DGA Domain Rotation Detection
 *
 * Targets the MD5+Calendar DGA pattern used for C2 fallback:
 *   seed = TLD + ISO_week_number + calendar_year
 *   hash = MD5(seed) -> first hex chars -> resolved to fallback domain
 *
 * R8 impact: DGA function names (generateFallbacks, md5Hex, hashToOctets)
 * are fully inlined/renamed. However, the DGA uses Android framework APIs
 * (MessageDigest, Calendar) which survive as type references, plus the
 * anti-debug TracerPid regex survives (co-located in evasion code).
 *
 * Best detection on debug builds. Release build detection relies on
 * behavioral combination of MD5 + Calendar + anti-debug + C2 beacon.
 *
 * References:
 *   MITRE ATT&CK Mobile: T1568.002 (Domain Generation Algorithms)
 *   MASTG: MASTG-CTRL-0014
 *   Family: SharkBot V2.8 DGA (research/06)
 *
 * False positives:
 *   Many apps use MD5 + Calendar. Mitigated by requiring TracerPid
 *   anti-debug (evasion co-occurrence) or C2 beacon path.
 */

rule SkyWeather_DGA_Domain_Rotation
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "MD5+Calendar DGA with anti-debug — SharkBot V2.8 shape"
        family      = "SkyWeather"
        mitre       = "T1568.002"
        mastg       = "MASTG-CTRL-0014"
        severity    = "high"
        fp_rate     = "medium alone, low with co-occurrence conditions"

    strings:
        // DGA ingredients (Android framework references, survive R8)
        $md5         = "MD5"
        $calendar    = "Ljava/util/Calendar;"
        $greg_cal    = "Ljava/util/GregorianCalendar;"
        $msg_digest  = "Ljava/security/MessageDigest;"

        // Anti-debug co-located in evasion layer (survived R8)
        $anti_debug  = "TracerPid"

        // DGA function names (debug builds only — R8 removes)
        $fn_generate = "generateFallbacks"
        $fn_md5hex   = "md5Hex"
        $fn_octets   = "hashToOctets"
        $fn_resolve  = "resolveEndpoint"

        // DGA class name (debug builds only)
        $class_dga   = "DomainResolver"

        // C2 beacon (co-occurrence — DGA feeds into beacon endpoint)
        $beacon      = "api/v1/beacon"

    condition:
        uint32(0) == 0x0A786564 and
        (
            // Debug build: DGA class + function names
            ($class_dga and 2 of ($fn_*)) or
            // Debug build: DGA functions + beacon
            (1 of ($fn_*) and $beacon) or
            // Release build: MD5 + Calendar + anti-debug + beacon
            ($md5 and 1 of ($calendar, $greg_cal) and $anti_debug and $beacon) or
            // Release build: MessageDigest + Calendar + C2
            ($msg_digest and 1 of ($calendar, $greg_cal) and $beacon and $anti_debug)
        )
}
