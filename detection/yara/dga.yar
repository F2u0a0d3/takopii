/*
 * Takopii Detection Corpus — DGA Shape Rule (SharkBot V2.8)
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Detects MD5 + Calendar-based Domain Generation Algorithm pattern matching
 *   SharkBot V2.8 shape. Also catches lab variant that generates RFC1918 IPs
 *   via hashToOctets instead of public domains.
 */

rule Takopii_DGA_MD5_Calendar {
    meta:
        description = "Detects MD5+Calendar DGA pattern (SharkBot V2.8 shape)"
        author = "Takopii Framework"
        severity = "high"
        specimen = "stage-1-evasion"
        mitre = "T1437"

    strings:
        $md5 = "MessageDigest" ascii
        $md5_algo = "MD5" ascii
        $calendar = "Calendar" ascii
        $week = "WEEK_OF_YEAR" ascii
        $tld_xyz = ".xyz" ascii
        $tld_live = ".live" ascii
        $tld_top = ".top" ascii
        // Lab variant: IP generation instead of domain
        $hash_to = "hashToOctets" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $md5 and $md5_algo and $calendar and $week and
        (2 of ($tld_xyz, $tld_live, $tld_top) or $hash_to)
}
