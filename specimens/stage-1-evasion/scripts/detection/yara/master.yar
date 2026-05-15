/*
 * SkyWeather Forecast — Master YARA Ruleset
 *
 * Aggregates all detection rules for the stage-1-evasion specimen.
 * Run against APK or extracted classes.dex:
 *
 *   yara -r master.yar app-release.apk
 *   yara -r master.yar classes.dex
 *
 * Rules: 6 files, 8 rules total
 *   skyweather-banker-shape.yar     (1) — composite multi-signal banker shape
 *   anatsa-c2-protocol.yar          (2) — C2 beacon + config regex pack
 *   sms-otp-stealing.yar            (1) — SMS receiver + OTP extraction chain
 *   dcl-reflection-chain.yar        (1) — DexClassLoader modular loader
 *   ats-gesture-injection.yar       (1) — Automated Transfer System chain
 *   credential-exfil-taxonomy.yar   (2) — credential event types + overlay capture
 *   dga-domain-rotation.yar         (1) — MD5+Calendar DGA pattern
 *
 * Expected hits on release APK: >= 6 rules
 * Expected hits on debug APK: >= 8 rules (all)
 */

include "skyweather-banker-shape.yar"
include "anatsa-c2-protocol.yar"
include "sms-otp-stealing.yar"
include "dcl-reflection-chain.yar"
include "ats-gesture-injection.yar"
include "credential-exfil-taxonomy.yar"
include "dga-domain-rotation.yar"
