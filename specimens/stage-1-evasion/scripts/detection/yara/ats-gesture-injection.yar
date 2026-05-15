/*
 * SkyWeather Forecast — ATS (Automatic Transfer System) Detection
 *
 * Targets the Accessibility-driven automated transfer chain:
 *   C2 pushes ats_commands -> AtsEngine loads queue ->
 *   AccessibilityService detects target foreground ->
 *   ScreenReader finds nodes -> GestureInjector dispatches taps/text ->
 *   OTP auto-filled -> transfer confirmed
 *
 * This is the kill chain that SharkBot pioneered and Anatsa mirrored.
 * The ATS vocabulary (command types, completion events, auto_fill_otp)
 * is unique to banker malware — no legitimate app has this terminology.
 *
 * R8 survival: All ATS strings are runtime constants used in JSON parsing
 * and event logging. R8 cannot remove them.
 *
 * References:
 *   MITRE ATT&CK Mobile: T1417.001 (Keylogging), T1517 (Access Notifications)
 *   MASTG: MASTG-CTRL-0006
 *   Family: SharkBot ATS (research/06), Anatsa ATS (research/02)
 *
 * False positives:
 *   Zero expected. "ats_commands" + "auto_fill_otp" + "ats_complete"
 *   is a vocabulary no legitimate application uses.
 */

rule SkyWeather_ATS_Gesture_Injection
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "Automated Transfer System — C2-driven gesture injection chain"
        family      = "SkyWeather"
        mitre       = "T1417.001, T1517"
        mastg       = "MASTG-CTRL-0006"
        severity    = "critical"
        fp_rate     = "near-zero — ATS vocabulary is banker-exclusive"

    strings:
        // ATS command vocabulary (runtime JSON parsing constants)
        $ats_cmds    = "ats_commands"
        $ats_done    = "ats_complete"
        $ats_fail    = "ats_abort"
        $ats_read    = "ats_read"
        $ats_result  = "ats_result"
        $ats_screen  = "ats_screen_dump"

        // ATS action types (command dispatch vocabulary)
        $act_autofill = "auto_fill_otp"

        // Accessibility text injection (framework constants, survive R8)
        $a11y_settext = "ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE"
        $a11y_global  = "performGlobalAction"

        // ATS engine field names (survived R8 in string pool)
        $field_engine = "atsEngine"

    condition:
        uint32(0) == 0x0A786564 and
        (
            // Core ATS vocabulary: 3+ ATS command strings
            (3 of ($ats_*)) or
            // ATS + auto-fill: command queue + OTP injection
            ($ats_cmds and $act_autofill) or
            // Full ATS chain: commands + text injection + global actions
            (1 of ($ats_*) and $a11y_settext and $a11y_global) or
            // ATS engine binding: engine field + command vocabulary
            ($field_engine and 2 of ($ats_*))
        )
}
