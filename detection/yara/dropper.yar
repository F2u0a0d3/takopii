/*
 * Takopii Detection Corpus — Dropper Config-Download Rule
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Detects dropper pattern: config check endpoint + payload download with
 *   octet-stream fetch. Matches the config-then-download two-phase dropper shape.
 */

rule Takopii_Dropper_Config_Download {
    meta:
        description = "Detects dropper config check + payload download pattern"
        author = "Takopii Framework"
        severity = "high"
        specimen = "dropper"
        mitre = "T1437"

    strings:
        $cfg_check = "/api/v1/check" ascii wide
        $cfg_alt = "config_url" ascii wide
        $http_conn = "HttpURLConnection" ascii
        $fetch_bytes = "fetchBytes" ascii
        $write_bytes = "writeBytes" ascii
        $json_ok = "\"ok\"" ascii
        $octet_stream = "application/octet-stream" ascii wide

    condition:
        uint32(0) == 0x04034B50 and
        ($cfg_check or $cfg_alt) and
        $http_conn and
        ($fetch_bytes or $write_bytes or $octet_stream) and
        $json_ok
}
