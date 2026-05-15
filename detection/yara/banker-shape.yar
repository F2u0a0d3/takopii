/*
 * Takopii Detection Corpus — Overlay Banker Shape Rule
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Detects overlay banker with AccessibilityService + NotificationListenerService
 *   + SMS multi-vector credential capture. Covers both TYPE_APPLICATION_OVERLAY and
 *   the newer TYPE_ACCESSIBILITY_OVERLAY (2032) window types.
 */

rule Takopii_Overlay_Banker_Shape {
    meta:
        description = "Detects overlay banker with A11y + NLS + SMS multi-vector"
        author = "Takopii Framework"
        severity = "critical"
        specimen = "overlay-banker"
        mitre = "T1626"

    strings:
        $a11y_service = "AccessibilityService" ascii
        $a11y_event = "onAccessibilityEvent" ascii
        $nls = "NotificationListenerService" ascii
        $overlay_type = "TYPE_APPLICATION_OVERLAY" ascii
        $overlay_2032 = "TYPE_ACCESSIBILITY_OVERLAY" ascii
        $window_mgr = "WindowManager" ascii
        $add_view = "addView" ascii
        $sms_received = "SMS_RECEIVED" ascii

    condition:
        uint32(0) == 0x04034B50 and
        $a11y_service and $a11y_event and
        ($overlay_type or $overlay_2032) and
        $window_mgr and $add_view and
        ($nls or $sms_received)
}
