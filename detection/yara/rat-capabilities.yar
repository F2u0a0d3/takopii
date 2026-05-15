/*
 * Takopii Detection Corpus — RAT Capabilities Rules
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 *
 * Description:
 *   Detects RAT-class capabilities added in v0.1.0 expansion:
 *   Silent camera capture, ambient audio recording, screen streaming,
 *   touch/keylogging, TOTP authenticator scraping, call forwarding,
 *   contact manipulation, remote shell, factory reset, AV removal.
 *
 *   Family references: Brokewell, Crocodilus, FakeCall, TrickMo,
 *   ToxicPanda, Cerberus, BRATA, SpyNote
 */

rule Takopii_Silent_Camera_Capture {
    meta:
        description = "Silent camera capture without preview surface — Brokewell/SpyNote pattern"
        author = "Takopii Framework"
        severity = "high"
        mitre = "T1512"
        families = "Brokewell, SpyNote, Cerberus"

    strings:
        $camera2 = "CameraDevice" ascii
        $capture_req = "createCaptureRequest" ascii
        $image_reader = "ImageReader" ascii
        $no_preview = "newInstance" ascii
        $jpeg = "JPEG" ascii
        $flash_off = "FLASH_MODE_OFF" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $camera2 and $capture_req and $image_reader and
        ($jpeg or $flash_off or $no_preview)
}

rule Takopii_Ambient_Audio_Recording {
    meta:
        description = "Background microphone capture with chunked C2 upload — Brokewell/Cerberus pattern"
        author = "Takopii Framework"
        severity = "high"
        mitre = "T1429"
        families = "Brokewell, Cerberus, SpyNote, BRATA"

    strings:
        $audio_record = "AudioRecord" ascii
        $mic_source = "AudioSource" ascii
        $pcm = "PCM" ascii
        $encoding = "ENCODING_PCM_16BIT" ascii
        $start_recording = "startRecording" ascii
        $audio_content = "audio/" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $audio_record and $start_recording and
        ($pcm or $encoding or $mic_source) and
        $audio_content
}

rule Takopii_TOTP_Authenticator_Scrape {
    meta:
        description = "Accessibility-based TOTP code extraction from authenticator apps — Crocodilus pattern"
        author = "Takopii Framework"
        severity = "critical"
        mitre = "T1517"
        families = "Crocodilus"
        note = "First commodity banker to specifically target Google Authenticator"

    strings:
        $google_auth = "com.google.android.apps.authenticator2" ascii
        $ms_auth = "com.azure.authenticator" ascii
        $authy = "com.authy.authy" ascii
        $aegis = "com.beemdevelopment.aegis" ascii
        $totp_regex = { 5C 64 7B 33 } // \d{3  — start of TOTP regex pattern

    condition:
        uint32(0) == 0x04034B50 and
        2 of ($google_auth, $ms_auth, $authy, $aegis) and
        $totp_regex
}

rule Takopii_Call_Forwarding_Abuse {
    meta:
        description = "USSD call forwarding activation — FakeCall pattern"
        author = "Takopii Framework"
        severity = "high"
        mitre = "T1616"
        families = "FakeCall, Cerberus, BRATA"

    strings:
        $ussd_forward = "*21*" ascii
        $ussd_cancel = "##21#" ascii
        $ussd_no_reply = "*61*" ascii
        $ussd_busy = "*67*" ascii
        $call_phone = "CALL_PHONE" ascii
        $telecom = "TelecomManager" ascii

    condition:
        uint32(0) == 0x04034B50 and
        ($ussd_forward or $ussd_cancel or $ussd_no_reply or $ussd_busy) and
        ($call_phone or $telecom)
}

rule Takopii_Factory_Reset_Wipe {
    meta:
        description = "Remote factory reset capability — BRATA anti-forensics pattern"
        author = "Takopii Framework"
        severity = "critical"
        mitre = "T1447"
        families = "BRATA"

    strings:
        $recovery_wipe = "recovery" ascii
        $wipe_data = "--wipe_data" ascii
        $master_clear = "MASTER_CLEAR" ascii
        $factory_reset_cmd = "FACTORY_RESET" ascii

    condition:
        uint32(0) == 0x04034B50 and
        ($wipe_data or $master_clear or $factory_reset_cmd) and
        $recovery_wipe
}

rule Takopii_Security_App_Removal {
    meta:
        description = "Automated security/AV app detection and removal — TrickMo/SOVA pattern"
        author = "Takopii Framework"
        severity = "high"
        mitre = "T1629.001"
        families = "TrickMo, SOVA, BRATA, Cerberus"

    strings:
        $avast = "com.avast.android" ascii
        $kaspersky = "com.kaspersky" ascii
        $bitdefender = "com.bitdefender" ascii
        $malwarebytes = "org.malwarebytes" ascii
        $norton = "com.symantec" ascii
        $delete_pkg = "REQUEST_DELETE_PACKAGES" ascii
        $uninstall = "ACTION_UNINSTALL_PACKAGE" ascii

    condition:
        uint32(0) == 0x04034B50 and
        3 of ($avast, $kaspersky, $bitdefender, $malwarebytes, $norton) and
        ($delete_pkg or $uninstall)
}

rule Takopii_RAT_Combined_Shape {
    meta:
        description = "Combined RAT capabilities — camera + audio + screen + shell in single APK"
        author = "Takopii Framework"
        severity = "critical"
        mitre = "T1512, T1429, T1513"
        families = "Brokewell (full RAT), SpyNote"
        note = "Composite rule — any 4 of 6 RAT capabilities in one APK"

    strings:
        $camera = "CameraDevice" ascii
        $audio = "AudioRecord" ascii
        $screen = "VirtualDisplay" ascii
        $location = "LocationManager" ascii
        $shell = "getRuntime" ascii
        $contacts = "ContactsContract" ascii
        $keylog = "AccessibilityEvent" ascii

    condition:
        uint32(0) == 0x04034B50 and
        4 of them
}
