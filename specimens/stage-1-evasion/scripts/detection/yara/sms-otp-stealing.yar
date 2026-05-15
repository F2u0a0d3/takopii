/*
 * SkyWeather Forecast — SMS OTP Interception Detection
 *
 * Targets the SMS receiver + OTP extraction chain:
 *   SmsInterceptor.onReceive() -> SmsMessage.getMessageBody() ->
 *   OtpExtractor.extract() -> CredentialStore.capture(sms_otp_)
 *
 * R8 survival: SmsInterceptor class name kept (manifest-bound receiver).
 * SMS API strings survive (Android framework references). Event type
 * strings survive (runtime-used constants).
 *
 * References:
 *   MITRE ATT&CK Mobile: T1412 (Capture SMS Messages)
 *   MASTG: MASTG-CTRL-0007
 *   Family: Anatsa, SharkBot, FluBot
 *
 * False positives:
 *   SMS-based 2FA apps legitimately use SmsMessage + getMessageBody.
 *   Mitigated by requiring credential event types (sms_raw, sms_otp_)
 *   which no legitimate app uses.
 */

rule SkyWeather_SMS_OTP_Stealing
{
    meta:
        author      = "Takopii Detection Corpus"
        description = "SMS receiver + OTP extraction + credential capture chain"
        family      = "SkyWeather"
        mitre       = "T1412"
        mastg       = "MASTG-CTRL-0007"
        severity    = "critical"
        fp_rate     = "low — sms_raw/sms_otp_ event types eliminate legit SMS apps"

    strings:
        // Manifest-bound SMS receiver (R8-surviving)
        $class_sms   = "com/skyweather/forecast/core/SmsInterceptor"

        // Android SMS API (framework references, always survive)
        $api_receive = "SMS_RECEIVED"
        $api_message = "SmsMessage"
        $api_body    = "getMessageBody"
        $api_intent  = "getMessagesFromIntent"

        // Credential event type strings (specimen-specific)
        $evt_sms_raw = "sms_raw"
        $evt_sms_ctx = "sms_ctx"
        $evt_sms_otp = "sms_otp_"
        $evt_otp_sms = "otp_sms"

    condition:
        uint32(0) == 0x0A786564 and
        (
            // High confidence: specimen class + event types
            ($class_sms and 1 of ($evt_*)) or
            // SMS API triad + credential event type
            (2 of ($api_*) and 1 of ($evt_*)) or
            // Event taxonomy alone — 3+ SMS event types is banker-only
            (3 of ($evt_*))
        )
}
