/*
 * SkyWeather Forecast — Banker Shape Detection (Master Rule)
 *
 * Catches the composite banker shape: C2 protocol + credential taxonomy +
 * ATS vocabulary + manifest-bound offensive services. Fires on extracted
 * classes.dex from both debug and R8-processed release APKs.
 *
 * Scoring: requires strings from at least 4 of 6 independent categories.
 * Each category targets a different functional layer of the banker.
 *
 * Usage:
 *   # Extract DEX from APK (standard analysis pipeline):
 *   unzip -o app-release.apk classes.dex -d /tmp/scan
 *   yara skyweather-banker-shape.yar /tmp/scan/classes.dex
 *   # For multi-dex debug APKs, scan all:
 *   yara skyweather-banker-shape.yar /tmp/scan/classes*.dex
 *
 * References:
 *   MITRE ATT&CK Mobile: T1437 (Network), T1417 (Input Capture)
 *   MASTG: MASTG-CTRL-0006
 *   Family: Anatsa-shape / SharkBot-shape
 */

rule SkyWeather_Banker_Shape
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "SkyWeather Forecast specimen — composite banker shape"
        family      = "SkyWeather"
        mitre       = "T1437, T1417, T1411, T1412, T1409"
        mastg       = "MASTG-CTRL-0006"
        severity    = "critical"
        fp_rate     = "low — 4-of-6 category threshold eliminates single-surface hits"

    strings:
        // Category A: Manifest-bound offensive services
        $svc_a11y    = "com/skyweather/forecast/core/AccessibilityEngine"
        $svc_nls     = "com/skyweather/forecast/core/NotificationEngine"
        $svc_sms     = "com/skyweather/forecast/core/SmsInterceptor"
        $svc_sync    = "com/skyweather/forecast/core/SyncTask"
        $svc_update  = "com/skyweather/forecast/core/UpdateChannel"

        // Category B: C2 protocol
        $c2_beacon   = "api/v1/beacon"
        $c2_payload  = "update_cache.dex"
        $c2_kill     = "\"kill\":true"
        $c2_target   = "target_list"

        // Category C: Credential event taxonomy
        $evt_opwd    = "overlay_pwd"
        $evt_ousr    = "overlay_usr"
        $evt_otp_a   = "otp_a11y"
        $evt_otp_n   = "otp_nls"
        $evt_otp_s   = "otp_sms"
        $evt_sms_r   = "sms_raw"
        $evt_sms_c   = "sms_ctx"

        // Category D: ATS vocabulary
        $ats_cmd     = "ats_commands"
        $ats_done    = "ats_complete"
        $ats_fail    = "ats_abort"
        $ats_otp     = "auto_fill_otp"
        $ats_target  = "target_lost_foreground"

        // Category E: Dynamic loading
        $dcl         = "DexClassLoader"
        $cfg_payload = "payload_url"

        // Category F: Anti-debug
        $adbg_proc   = "/proc/self/status"
        $adbg_tracer = "TracerPid"

    condition:
        uint32(0) == 0x0A786564 and

        // Require 4 of 6 categories to fire (composite banker signal)
        (
            (2 of ($svc_*))   and (2 of ($c2_*))  and (3 of ($evt_*)) and (2 of ($ats_*))
        ) or (
            (2 of ($svc_*))   and (2 of ($c2_*))  and (3 of ($evt_*)) and ($dcl or $cfg_payload)
        ) or (
            (2 of ($svc_*))   and (2 of ($c2_*))  and (2 of ($ats_*)) and ($dcl or $cfg_payload)
        ) or (
            (2 of ($svc_*))   and (3 of ($evt_*)) and (2 of ($ats_*)) and ($dcl or $cfg_payload)
        ) or (
            (2 of ($c2_*))    and (3 of ($evt_*)) and (2 of ($ats_*)) and ($dcl or $cfg_payload)
        ) or (
            (2 of ($svc_*))   and (2 of ($c2_*))  and (3 of ($evt_*)) and ($adbg_proc and $adbg_tracer)
        ) or (
            (2 of ($svc_*))   and (2 of ($c2_*))  and (2 of ($ats_*)) and ($adbg_proc and $adbg_tracer)
        ) or (
            (2 of ($c2_*))    and (3 of ($evt_*)) and (2 of ($ats_*)) and ($adbg_proc and $adbg_tracer)
        )
}
