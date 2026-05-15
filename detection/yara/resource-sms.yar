/*
 * Takopii Detection Corpus — Resource-Externalized SMS Stealer Rule
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Detects SMS stealer with URI components externalized to Android resources
 *   (resources.arsc). Evasion technique: move content://sms URI components
 *   into string resources so they don't appear in classes.dex.
 *   NOTE: Scan resources.arsc, not classes.dex.
 */

rule Takopii_Resource_SMS_Stealer {
    meta:
        description = "Detects SMS stealer with URI components externalized to resources"
        author = "Takopii Framework"
        severity = "high"
        note = "Scan resources.arsc, not classes.dex"

    strings:
        $scheme = "content_scheme" ascii wide
        $auth = "content_auth" ascii wide
        $path = "content_path" ascii wide
        $col_a = "col_a" ascii wide
        $col_b = "col_b" ascii wide

    condition:
        $scheme and $auth and $path and ($col_a or $col_b)
}
