/*
 * Takopii Detection Corpus — intArrayOf String Encoding Rule
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Detects arithmetic-shift string encoding via integer arrays. Heuristic rule
 *   that may false-positive on apps with heavy integer data — combine with other
 *   rules for higher confidence.
 */

rule Takopii_IntArray_String_Encoding {
    meta:
        description = "Detects arithmetic-shift string encoding via integer arrays"
        author = "Takopii Framework"
        severity = "medium"
        specimen = "stage-1-evasion"
        note = "Heuristic — may FP on apps with heavy integer data. Combine with other rules."

    strings:
        // Common pattern: multiple intArrayOf followed by decode function
        $intarray = "intArrayOf" ascii
        $shift = "SHIFT" ascii
        $tochar = ".toChar()" ascii
        $decode = "decode" ascii
        $chararray = "CharArray" ascii

    condition:
        uint32(0) == 0x04034B50 and
        #intarray > 5 and
        $shift and $tochar and ($decode or $chararray)
}
