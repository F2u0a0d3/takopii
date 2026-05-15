/*
 * Takopii Detection Corpus — SMS Stealer Rules
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Detects SMS data access via ContentResolver with exfiltration patterns.
 *   Two variants: one using androguard module, one standalone (no module dependency).
 *   For specimens with string externalization, scan resources.arsc not just classes.dex.
 */

import "androguard"

rule Takopii_SMS_ContentResolver_Pattern {
    meta:
        description = "Detects SMS data access via ContentResolver with generic key exfiltration"
        author = "Takopii Framework"
        severity = "high"
        specimen = "sms-stealer"
        mitre = "T1582"

    strings:
        $cr_query = "content://sms" ascii wide
        $cr_inbox = "inbox" ascii wide
        $col_addr = "address" ascii wide
        $col_body = "body" ascii wide
        $col_date = "date" ascii wide
        $json_obj = "JSONObject" ascii
        $http_post = "HttpURLConnection" ascii
        // Resource-externalized variants
        $res_scheme = "content_scheme" ascii wide
        $res_auth = "content_auth" ascii wide

    condition:
        androguard.package_name(/com\.\w+\.\w+/) and
        (
            ($cr_query or ($cr_inbox and 2 of ($col_addr, $col_body, $col_date))) or
            ($res_scheme and $res_auth)
        ) and
        ($json_obj or $http_post)
}

rule Takopii_SMS_ContentResolver_Pattern_NoModule {
    meta:
        description = "Detects SMS stealer pattern (no androguard dependency)"
        author = "Takopii Framework"
        severity = "high"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $cr_query = "content://sms" ascii wide
        $res_scheme = "content_scheme" ascii wide
        $res_auth = "content_auth" ascii wide
        $http_post = "HttpURLConnection" ascii

    condition:
        $zip_magic at 0 and
        ($cr_query or ($res_scheme and $res_auth)) and
        $http_post
}
