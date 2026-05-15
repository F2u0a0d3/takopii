/*
 * Takopii Detection Corpus — Frontier Rules (2025-2026)
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Frontier detection rules covering emerging 2025-2026 banker primitives:
 *   TYPE_ACCESSIBILITY_OVERLAY (2032), hidden VNC via MediaProjection,
 *   NFC relay / ghost-tap, residential proxy SOCKS5, SSO MFA auto-approve,
 *   Yamux protocol multiplexer, early-init ContentProvider hook,
 *   SMS worm spreading, and screen-reader ATS tree traversal.
 */

import "androguard"

rule Takopii_A11y_Overlay_2032 {
    meta:
        description = "Detects TYPE_ACCESSIBILITY_OVERLAY (2032) credential capture — bypasses SYSTEM_ALERT_WINDOW"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1626"
        note = "Crocodilus (March 2025) first family observed using this window type"

    strings:
        $type_2032 = { 00 07 F0 } // 2032 in big-endian short
        $type_2032_str = "TYPE_ACCESSIBILITY_OVERLAY" ascii
        $type_const = "2032" ascii
        $wm_addview = "addView" ascii
        $a11y_service = "AccessibilityService" ascii
        $layout_params = "LayoutParams" ascii
        $session_expired = "Session Expired" ascii wide
        $sign_in = "Sign In" ascii wide

    condition:
        uint32(0) == 0x04034B50 and
        ($type_2032 or $type_2032_str or $type_const) and
        $a11y_service and $wm_addview and
        ($session_expired or $sign_in or $layout_params)
}

rule Takopii_HiddenVnc_MediaProjection {
    meta:
        description = "Detects MediaProjection + VirtualDisplay + ImageReader combo (hidden VNC)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1513"
        note = "Klopatra pattern — Virbox-protected hidden VNC"

    strings:
        $mp = "MediaProjection" ascii
        $vd = "VirtualDisplay" ascii
        $ir = "ImageReader" ascii
        $create_vd = "createVirtualDisplay" ascii
        $acquire = "acquireLatestImage" ascii
        $bitmap = "Bitmap" ascii
        $compress = "compress" ascii
        $a11y = "AccessibilityService" ascii
        $gesture = "GestureDescription" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $mp and $vd and $ir and
        $create_vd and $acquire and
        ($a11y or $gesture)
}

rule Takopii_NfcRelay_GhostTap {
    meta:
        description = "Detects NFC relay via HostApduService + TCP socket (ghost-tap pattern)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1646"
        note = "RatOn NFC relay pattern"

    strings:
        $hce = "HostApduService" ascii
        $apdu = "processCommandApdu" ascii
        $socket = "java.net.Socket" ascii
        $data_out = "DataOutputStream" ascii
        $data_in = "DataInputStream" ascii
        $ppse = "2PAY.SYS.DDF01" ascii
        $select_aid = { 00 A4 04 00 }
        $relay = "relay" ascii nocase
        $nfc_relay = "NfcRelay" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $hce and $apdu and
        ($socket or $data_out) and
        ($ppse or $select_aid or $relay or $nfc_relay)
}

rule Takopii_ResidentialProxy_SOCKS5 {
    meta:
        description = "Detects SOCKS5 proxy server in non-VPN app (Mirax monetization pattern)"
        author = "Takopii Framework"
        severity = "high"
        specimen = "overlay-banker"
        mitre = "T1090"

    strings:
        $server_socket = "ServerSocket" ascii
        $socks5_ver = { 05 } // SOCKS5 version byte
        $socks5_class = "SOCKS" ascii nocase
        $accept = ".accept()" ascii
        $relay = "relay" ascii nocase
        $connect_cmd = { 05 01 00 } // SOCKS5 CONNECT
        $bind_port = "1080" ascii
        $residential = "residential" ascii nocase
        $proxy = "Proxy" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $server_socket and
        ($socks5_class or $residential or ($accept and $proxy)) and
        ($bind_port or $connect_cmd)
}

rule Takopii_SsoHijacker_MFA_AutoApprove {
    meta:
        description = "Detects SSO MFA auto-approve pattern (Vespertine — May 2026)"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1517"

    strings:
        $sso1 = "com.azure.authenticator" ascii
        $sso2 = "com.okta.android" ascii
        $sso3 = "com.duosecurity.duomobile" ascii
        $sso4 = "com.google.android.apps.authenticator2" ascii
        $sso5 = "com.authy.authy" ascii
        $approve1 = "approve" ascii nocase
        $approve2 = "confirm" ascii nocase
        $approve3 = "it's me" ascii nocase
        $approve4 = "onayla" ascii nocase
        $approve5 = "aprobar" ascii nocase
        $a11y = "AccessibilityService" ascii
        $click = "ACTION_CLICK" ascii
        $perform = "performAction" ascii

    condition:
        uint32(0) == 0x04034B50 and
        2 of ($sso1, $sso2, $sso3, $sso4, $sso5) and
        2 of ($approve1, $approve2, $approve3, $approve4, $approve5) and
        $a11y and ($click or $perform)
}

rule Takopii_YamuxProxy_Multiplexer {
    meta:
        description = "Detects Yamux protocol multiplexer (Mirax/Klopatra tunnel pattern)"
        author = "Takopii Framework"
        severity = "high"
        specimen = "overlay-banker"
        mitre = "T1090"

    strings:
        $yamux_str = "yamux" ascii nocase
        $type_data = "TYPE_DATA" ascii
        $type_ping = "TYPE_PING" ascii
        $type_goaway = "TYPE_GO_AWAY" ascii
        $type_wup = "TYPE_WINDOW_UPDATE" ascii
        $flag_syn = "FLAG_SYN" ascii
        $flag_fin = "FLAG_FIN" ascii
        $flag_rst = "FLAG_RST" ascii
        $header_size = "HEADER_SIZE" ascii
        $stream_id = "streamId" ascii
        $mux_socket = "muxSocket" ascii
        $native_encode = "yamuxEncode" ascii
        $native_decode = "yamuxDecode" ascii

    condition:
        uint32(0) == 0x04034B50 and
        ($yamux_str or 2 of ($type_data, $type_ping, $type_goaway, $type_wup)) and
        ($flag_syn or $flag_fin) and
        ($header_size or $stream_id or $mux_socket or $native_encode)
}

rule Takopii_EarlyInitProvider_NoOp {
    meta:
        description = "Detects ContentProvider with no-op query/insert/update/delete (init hook)"
        author = "Takopii Framework"
        severity = "medium"
        specimen = "overlay-banker"
        mitre = "T1398"

    strings:
        $provider = "ContentProvider" ascii
        $oncreate = "onCreate" ascii
        $query_null = "query" ascii
        $insert_null = "insert" ascii
        $env_gate = "EnvironmentGate" ascii
        $string_dec = "StringDecoder" ascii
        $early_init = "EarlyInit" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $provider and $oncreate and
        ($env_gate or $string_dec or $early_init)
}

rule Takopii_SmsWorm_Spreading {
    meta:
        description = "Detects SMS worm with lure templates and contact-targeted spreading"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1582"

    strings:
        $sms_send = "sendTextMessage" ascii
        $sms_multi = "sendMultipartTextMessage" ascii
        $contacts = "ContactsContract" ascii
        $lure1 = "package delivery" ascii nocase
        $lure2 = "pending payment" ascii nocase
        $lure3 = "verify your account" ascii nocase
        $lure4 = "shared photos" ascii nocase
        $template = "{name}" ascii
        $url_placeholder = "{url}" ascii
        $rate_limit = "delay" ascii

    condition:
        uint32(0) == 0x04034B50 and
        ($sms_send or $sms_multi) and
        $contacts and
        (2 of ($lure1, $lure2, $lure3, $lure4) or ($template and $url_placeholder))
}

rule ScreenReader_ATS_TreeTraversal {
    meta:
        description = "Detects AccessibilityNodeInfo recursive tree traversal pattern used for ATS screen reading"
        author = "Takopii Detection Engineering"
        reference = "specimens/stage-1-evasion/../core/ScreenReader.kt"
        family = "SkyWeather/Anatsa-shape"

    strings:
        // ScreenReader method signatures
        $getRootInActiveWindow = "getRootInActiveWindow"
        $getChild = "getChild"
        $viewIdResourceName = "viewIdResourceName"
        $findNodeById = "findNodeById"
        $findNodeByText = "findNodeByText"
        $extractAllText = "extractAllText"
        $findClickableNodes = "findClickableNodes"
        $findEditableNodes = "findEditableNodes"

        // Screen-state detection keywords (ATS navigation)
        $screen_transfer = "Transfer" ascii
        $screen_confirm = "Confirm" ascii
        $screen_code = "code" ascii
        $screen_successful = "Successful" ascii

        // ATS composition: tree traversal + action dispatch
        $performAction = "performAction"
        $ACTION_SET_TEXT = "ACTION_SET_TEXT"
        $ACTION_CLICK = "ACTION_CLICK"

    condition:
        androguard.package_name(/skyweather|docreader/) and
        $getRootInActiveWindow and $getChild and
        (
            // Full ScreenReader shape: tree traversal + text extraction
            ($viewIdResourceName and 2 of ($findNodeById, $findNodeByText, $extractAllText,
                $findClickableNodes, $findEditableNodes)) or
            // ATS composition: read screen + inject actions
            ($getRootInActiveWindow and $getChild and $performAction and
                ($ACTION_SET_TEXT or $ACTION_CLICK) and
                2 of ($screen_transfer, $screen_confirm, $screen_code, $screen_successful))
        )
}
