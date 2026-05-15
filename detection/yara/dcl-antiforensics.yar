/*
 * Takopii Detection Corpus — DexClassLoader Anti-Forensics Rule
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Detects DexClassLoader with file deletion — the payload load + cleanup
 *   anti-forensics pattern. Banker fetches DEX from C2, loads via DCL,
 *   then deletes from disk. Forensics on device sees no DEX file.
 */

rule Takopii_DCL_AntiForensics {
    meta:
        description = "Detects DexClassLoader with file deletion (payload load + cleanup)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "stage-1-evasion"
        mitre = "T1407"

    strings:
        $dcl = "DexClassLoader" ascii
        $class_forname = "Class.forName" ascii
        $get_method = "getDeclaredMethod" ascii
        $invoke = ".invoke(" ascii
        $file_delete = ".delete()" ascii
        $cache_data = ".cache_data" ascii
        $update_cache = ".update_cache" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $dcl and
        ($class_forname or $get_method or $invoke) and
        $file_delete and
        ($cache_data or $update_cache)
}
