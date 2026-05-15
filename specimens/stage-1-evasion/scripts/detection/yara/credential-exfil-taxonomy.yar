/*
 * SkyWeather Forecast — Credential Exfiltration Taxonomy Detection
 *
 * Targets the credential event type vocabulary — the taxonomy used to
 * classify stolen data before exfil:
 *
 *   overlay_pwd / overlay_usr  — overlay-captured credentials
 *   otp_a11y / otp_nls / otp_sms — OTP by capture vector
 *   sms_raw / sms_ctx — raw SMS + context
 *   ats_complete / ats_abort — ATS outcome events
 *
 * This taxonomy is the fingerprint of a banker trojan's credential store.
 * No legitimate application classifies captured text into these categories.
 *
 * R8 survival: All event type strings are used at runtime for JSON
 * serialization and event routing. R8 cannot remove them.
 *
 * References:
 *   MITRE ATT&CK Mobile: T1417 (Input Capture), T1412 (SMS), T1411 (Clipboard)
 *   MASTG: MASTG-CTRL-0006, MASTG-CTRL-0007
 *   Family: Anatsa, SharkBot, ERMAC2 (all use similar event taxonomies)
 *
 * False positives:
 *   Zero expected. No legitimate app uses overlay_pwd + otp_a11y + sms_raw.
 */

rule SkyWeather_Credential_Taxonomy
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "Credential event type taxonomy — banker exfil classification"
        family      = "SkyWeather"
        mitre       = "T1417, T1412, T1411"
        mastg       = "MASTG-CTRL-0006, MASTG-CTRL-0007"
        severity    = "critical"
        fp_rate     = "zero — vocabulary is exclusive to banker trojans"

    strings:
        // Overlay credential capture events
        $overlay_pwd  = "overlay_pwd"
        $overlay_usr  = "overlay_usr"
        $overlay_pass = "overlay_password"
        $overlay_user = "overlay_username"

        // OTP capture events (by vector)
        $otp_a11y    = "otp_a11y"
        $otp_nls     = "otp_nls"
        $otp_sms     = "otp_sms"

        // SMS capture events
        $sms_raw     = "sms_raw"
        $sms_ctx     = "sms_ctx"
        $sms_otp     = "sms_otp_"
        $sms_body    = "sms_body"

        // ATS outcome events
        $ats_complete = "ats_complete"
        $ats_abort    = "ats_abort"
        $ats_read     = "ats_read"

        // Overlay renderer field (survived R8 string pool)
        $renderer     = "overlayRenderer"

    condition:
        (uint32(0) == 0x0A786564 or uint16(0) == 0x4B50) and
        (
            // Overlay credential pair — both pwd + usr event types
            ($overlay_pwd and $overlay_usr) or
            // Multi-vector OTP — captures OTP from 2+ sources
            (2 of ($otp_a11y, $otp_nls, $otp_sms)) or
            // Cross-surface taxonomy — events from 3+ capture vectors
            (1 of ($overlay_*) and 1 of ($otp_*) and 1 of ($sms_*)) or
            // Full taxonomy — 5+ distinct event types
            (5 of them)
        )
}


rule SkyWeather_Overlay_Credential_Capture
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "Overlay-specific credential capture indicators"
        family      = "SkyWeather"
        mitre       = "T1411"
        mastg       = "MASTG-CTRL-0006"
        severity    = "high"
        fp_rate     = "very low — overlay_pwd/usr pair is banker-exclusive"

    strings:
        $overlay_pwd  = "overlay_pwd"
        $overlay_usr  = "overlay_usr"
        $renderer     = "overlayRenderer"

        // Overlay rendering class name (debug builds)
        $class_overlay = "OverlayRenderer"

        // Accessibility overlay type constant (debug builds)
        // TYPE_ACCESSIBILITY_OVERLAY = 2032 — inlined in release
        $type_overlay  = "TYPE_ACCESSIBILITY_OVERLAY"

    condition:
        (uint32(0) == 0x0A786564 or uint16(0) == 0x4B50) and
        ($overlay_pwd and $overlay_usr) and
        (1 of ($renderer, $class_overlay, $type_overlay))
}
