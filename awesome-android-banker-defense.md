# Awesome Android Banker Defense

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A curated list of resources for analyzing, detecting, and defending against Android banker malware. Maintained as part of the [Takopii](https://github.com/F2u0a0d3/takopii) project.

Contributions welcome. See [Contributing](#contributing) at the bottom.

---

## Contents

- [Threat Intelligence Reports](#threat-intelligence-reports)
- [Open-Source Trainer Apps](#open-source-trainer-apps)
- [Analysis Tools](#analysis-tools)
- [Detection Frameworks](#detection-frameworks)
- [RASP Products](#rasp-products)
- [MTD Products](#mtd-products)
- [Standards and Frameworks](#standards-and-frameworks)
- [Educational Resources](#educational-resources)
- [Frida Script Collections](#frida-script-collections)
- [Contributing](#contributing)

---

## Threat Intelligence Reports

Public reports documenting real-world Android banker families. Primary references for understanding attacker tradecraft.

### Cleafy

- [Anatsa / TeaBot / Toddler](https://www.cleafy.com/cleafy-labs/anatsa-evolution) - Multi-stage dropper targeting 600+ banking apps; ATS, AccessibilityService abuse, GitHub-as-CDN payload delivery.
- [Klopatra](https://www.cleafy.com/cleafy-labs/) - IPTV sideload vector, Virbox native protection, Yamux-multiplexed hidden VNC remote control.
- [Copybara / BRATA Evolution](https://www.cleafy.com/cleafy-labs/) - Factory reset after fraud, GPS tracking, keylogging via AccessibilityService.

### ThreatFabric

- [Octo / ExobotCompact](https://www.threatfabric.com/blogs/octo-new-odf-banking-trojan.html) - Remote access trojan with VNC-like screen streaming over AccessibilityService.
- [ERMAC 2.0](https://www.threatfabric.com/blogs/ermac-another-cerberus-reborn.html) - Cerberus successor, 467 overlay targets, Telegram C2.
- [Mirax](https://www.threatfabric.com/) - Meta-ads distribution, SOCKS5 residential proxy monetization, Yamux multiplexer.
- [Vespertine](https://www.threatfabric.com/) - Corporate BYOD targeting, SSO notification hijack, MFA push auto-approve via AccessibilityService.

### Zscaler ThreatLabz

- [SharkBot](https://www.zscaler.com/blogs/security-research/technical-analysis-of-sharkbot) - ATS pioneer, MD5+Calendar DGA (V0-V2.8), anti-emulator battery, direct APK drop.
- [SharkBot V2 Evolution](https://www.zscaler.com/blogs/security-research/) - DGA algorithm progression, cookie-stealing module, upgraded anti-analysis.

### NCC Group

- [SharkBot Threat Advisory](https://research.nccgroup.com/2022/03/03/sharkbot-a-new-generation-android-banking-trojan-being-distributed-on-google-play-store/) - Play Store distribution analysis, ATS workflow documentation.

### ESET

- [FluBot](https://www.welivesecurity.com/) - SMS worm propagation, contact harvesting, fake delivery notifications.
- [Apex](https://www.welivesecurity.com/) - AI-pipelined per-build polymorphism, per-victim ML-generated overlays, WhatsApp/Telegram distribution.

### Lookout

- [Drelock](https://www.lookout.com/threat-intelligence/) - First commodity banker using TEE / TrustZone offload for key operations beyond Frida reach.
- [BancaMarStealer](https://www.lookout.com/threat-intelligence/) - Latin America banking trojan family analysis.

### Zimperium

- [Mobile Banking Heists Report](https://www.zimperium.com/mobile-banking-heists/) - Annual survey of active banker families, global distribution, technique frequency.
- [RatOn](https://www.zimperium.com/) - NFC relay / ghost-tap primitive for contactless payment fraud.

### bin.re

- [Anatsa Deobfuscation](https://bin.re/) - Technical reverse-engineering of Anatsa string obfuscation and DexClassLoader chain.

### Other Notable Sources

- [Cyble Research](https://cyble.com/) - Regular Android banker family analyses and IOC feeds.
- [Kaspersky Securelist](https://securelist.com/) - In-depth mobile threat landscape reports.
- [Check Point Research](https://research.checkpoint.com/) - Banker family dissections and distribution campaign tracking.

---

## Open-Source Trainer Apps

Deliberately vulnerable Android applications for practicing analysis and bypass techniques.

- [Damn Vulnerable Bank (DVBank)](https://github.com/rewanthtammana/Damn-Vulnerable-Bank) - **Primary trainer.** MIT-licensed banking-shaped app with insecure storage, IDOR, weak crypto, exported components, OkHttp cert pinning, RootBeer root detection, Frida detection. Operator-controlled victim app.
- [DIVA (Damn Insecure and Vulnerable App)](https://github.com/payatu/diva-android) - Classic Android vulnerability trainer covering 13 challenge categories.
- [allsafe](https://github.com/nicholaschum/allsafe) - Intentionally vulnerable Android application for security assessment training.
- [InsecureShop](https://github.com/hax0rgb/InsecureShop) - Vulnerable e-commerce Android app for practicing common mobile vulnerabilities.
- [OWASP MSTG Apps](https://github.com/OWASP/owasp-mastg/tree/master/apps) - Official OWASP Mobile Application Security Testing Guide companion apps.
  - [UnCrackable-Level1](https://github.com/OWASP/owasp-mastg/tree/master/apps/android/MASTG-APP-0003) - Root detection + secret extraction challenge.
  - [UnCrackable-Level2](https://github.com/OWASP/owasp-mastg/tree/master/apps/android/MASTG-APP-0004) - Anti-tampering + native library challenge.
  - [UnCrackable-Level3](https://github.com/OWASP/owasp-mastg/tree/master/apps/android/MASTG-APP-0005) - Advanced anti-instrumentation challenge.
- [InjuredAndroid](https://github.com/B3nac/InjuredAndroid) - CTF-style Android app with progressive difficulty challenges.
- [AndroGoat](https://github.com/satishpatnayak/AndroGoat) - Kotlin-based vulnerable app covering OWASP Mobile Top 10.
- [Oversecured Vulnerable Android App](https://github.com/nicholaschum/allsafe) - Vulnerable by design for testing static analyzers.

---

## Analysis Tools

### Static Analysis

- [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Automated static + dynamic analysis. Docker-deployable. Supports custom YARA rule volumes. Takopii ships custom banker-shape rules for MobSF integration.
- [jadx](https://github.com/skylot/jadx) - DEX-to-Java decompiler with GUI and CLI. Primary decompilation tool for banker APK analysis.
- [apktool](https://github.com/iBotPeaches/Apktool) - APK reverse engineering: decode resources, rebuild, sign. Manifest and smali extraction.
- [dex2jar](https://github.com/pxb1988/dex2jar) - DEX to JAR conversion for JD-GUI or CFR decompilation.
- [APKLeaks](https://github.com/dwisiswant0/apkleaks) - Scan APK for URIs, endpoints, secrets. Useful for C2 endpoint extraction from banker samples.
- [androguard](https://github.com/androguard/androguard) - Python framework for Android APK analysis. Manifest parsing, DEX disassembly, call graph generation.
- [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) - Multi-decompiler GUI combining Procyon, CFR, JD-GUI, Fernflower for cross-reference.
- [ClassyShark](https://github.com/nicholaschum/allsafe) - Lightweight APK browser for quick class and method inspection.

### Dynamic Analysis

- [Frida](https://github.com/frida/frida) - Dynamic instrumentation toolkit. Core tool for hooking Java methods, bypassing protections, observing runtime behavior. See [Frida Script Collections](#frida-script-collections).
- [objection](https://github.com/sensepost/objection) - Frida-powered runtime exploration toolkit. Built-in SSL pinning disable, root detection bypass, filesystem exploration.
- [r2frida](https://github.com/nowsecure/r2frida) - Bridge between radare2 and Frida for combined static+dynamic analysis.
- [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Interactive HTTPS proxy for intercepting banker C2 traffic after pinning bypass.
- [Caido](https://caido.io/) - Modern HTTP proxy for web and mobile traffic interception. Alternative to Burp for C2 protocol analysis.
- [Burp Suite](https://portswigger.net/burp) - Industry-standard HTTP proxy. Community edition sufficient for banker C2 capture after pinning bypass.

### Network Analysis

- [Wireshark](https://www.wireshark.org/) - Packet capture and protocol analysis. JA3/JA4 TLS fingerprint extraction for banker C2 identification.
- [tcpdump](https://www.tcpdump.org/) - Command-line packet capture for on-device network monitoring.
- [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Scriptable HTTPS interception. Banker C2 typically does not pin its own traffic (see Takopii ANALYSIS.md S6).

### Forensics

- [ALEAPP](https://github.com/abrignoni/ALEAPP) - Android Logs Events And Protobuf Parser for post-compromise forensics.
- [scrcpy](https://github.com/Genymobile/scrcpy) - Screen mirroring for documenting banker overlay behavior without device interaction.

---

## Detection Frameworks

### YARA

- [YARA](https://github.com/VirusTotal/yara) - Pattern matching for malware classification. Takopii ships 24 YARA rules targeting banker-shape APK patterns.
- [yara-python](https://github.com/VirusTotal/yara-python) - Python bindings for YARA. Used in Takopii's MobSF pipeline integration.
- [yarGen](https://github.com/Neo23x0/yarGen) - YARA rule generator from malware samples. Useful for creating rules from new banker family variants.
- [YARA-CI](https://github.com/airbnb/yara-ci) - Continuous integration for YARA rules. Test banker-shape rules against known-good app corpus for false-positive control.

### Sigma

- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format for log-based detection. Takopii ships 34 Sigma rules targeting banker runtime behavior patterns.
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) - Command-line tool for Sigma rule conversion to SIEM-specific formats.
- [pySigma](https://github.com/SigmaHQ/pySigma) - Python library for Sigma rule processing and backend conversion.

### Frida-Based Monitoring

- [Takopii Master Monitor](https://github.com/F2u0a0d3/takopii/tree/main/detection/frida) - 37 Frida hooks covering AccessibilityService dispatch, overlay creation, DGA detection, ATS gesture injection, clipboard polling, evasion defeat.
- [House](https://github.com/nicholaschum/allsafe) - Frida-based Android analysis framework with web UI.

### Integrated Platforms

- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Orchestrates YARA + static analysis + dynamic analysis. Takopii's custom rule corpus mounts as MobSF custom-YARA volume for banker-specific scanning.
- [Quark Engine](https://github.com/nicholaschum/allsafe) - Android malware scoring system using rule-based behavior analysis.

---

## RASP Products

Runtime Application Self-Protection for banking apps. Categorized by accessibility for independent testing.

### Tier 1 -- Open / Free Trial

Products accessible for independent field-testing without sales engagement.

- [Talsec FreeRASP](https://github.com/nicholaschum/allsafe) - Open-source freemium RASP. GitHub-installable. Detect-only mode by default; operator chooses response. Community-accessible for field testing.
- [DoveRunner / AppSealing](https://www.appsealing.com/) - Free trial via cloud portal. Zero-code post-compile injection model. Upload APK, receive wrapped APK.
- [Build38 / OneSpan](https://www.build38.com/) - Vendor request access. Dynamic Security Profiles allow runtime policy updates without app rebuild.

### Tier 2 -- Sales-Gated

Products requiring sales engagement for evaluation access.

- [Promon SHIELD](https://promon.co/) - Claims pre-launch detection -- blocks Frida before main activity loads. Requires sales for SDK access.
- [GuardSquare DexGuard](https://www.guardsquare.com/dexguard) - Polymorphic obfuscation; every build produces different bytecode signatures. Includes ProGuard + DexGuard layers.

### Tier 3 -- Community Contribution

Products where field-test data comes from community contributors with existing access.

- [Verimatrix XTD](https://www.verimatrix.com/) - Threat-visibility platform with event dashboard. Extended Threat Defense beyond app hardening.
- [Zimperium zKeyBox](https://www.zimperium.com/) - White-box cryptography for key protection on compromised devices. DCA/ADCA/DFA/LDA resistant.
- [Quixxi](https://www.quixxi.com/) - Mobile app security platform with RASP and vulnerability scanning.

### Critical Gap (Documented)

No surveyed commercial RASP defends AccessibilityService abuse from a separate application. RASP hardens the target app against tampering but cannot prevent another app's AccessibilityService from reading the target app's UI text. Defense against cross-app overlay + A11y abuse requires MTD, not RASP alone. See Takopii ANALYSIS.md S10.

---

## MTD Products

Mobile Threat Defense -- cross-device detection that covers what RASP cannot (AccessibilityService abuse, overlay attacks from separate apps, device-level compromise).

- [Zimperium zIPS](https://www.zimperium.com/) - On-device ML-based threat detection. Detects malicious app behavior, network attacks, device exploits without cloud dependency.
- [Lookout Mobile Endpoint Security](https://www.lookout.com/) - Cloud-connected MTD covering app threats, phishing, device compromise. Banker family detection via behavioral analysis.
- [Microsoft Defender for Endpoint (Android)](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-android) - Enterprise MDM-integrated MTD. Web protection, malware scanning, conditional access integration.
- [Pradeo](https://www.pradeo.com/) - Mobile fleet security with app vetting, on-device threat detection, network protection.
- [CrowdStrike Falcon for Mobile](https://www.crowdstrike.com/) - Endpoint detection and response extended to mobile. Behavioral detection of banker-class threats.
- [Check Point Harmony Mobile](https://www.checkpoint.com/harmony/mobile/) - Network protection, OS exploit prevention, malicious app detection.

### RASP vs MTD -- When You Need Both

RASP protects the banking app from instrumentation and tampering. MTD protects the device from malicious apps that attack through AccessibilityService, overlay windows, and notification listeners. A banker malware using TYPE_ACCESSIBILITY_OVERLAY from a separate app bypasses every surveyed RASP but is detectable by MTD. Production banking deployments require both layers.

---

## Standards and Frameworks

### OWASP

- [OWASP MASTG v1.7.0](https://mas.owasp.org/MASTG/) - Mobile Application Security Testing Guide. Comprehensive testing methodology for Android and iOS. Control IDs (MASTG-CTRL-XX) referenced in every Takopii spoke.
- [OWASP MASVS v2.0.0](https://mas.owasp.org/MASVS/) - Mobile Application Security Verification Standard. Defines security requirements at three verification levels (L1/L2/R).
- [OWASP MASWE](https://mas.owasp.org/) - Mobile Application Security Weakness Enumeration. Weakness catalog cross-referenced in Takopii detection rules.
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) - High-level categorization of critical mobile security risks.

### MITRE

- [MITRE ATT&CK Mobile](https://attack.mitre.org/matrices/mobile/) - Adversary tactics and techniques for mobile platforms. Technique IDs (T1XXX) cross-referenced in every Takopii spoke and detection rule.
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Visual tool for mapping banker family techniques to the ATT&CK matrix.

### Google

- [Play Integrity API](https://developer.android.com/google/play/integrity) - Hardware-backed attestation for device and app integrity verification. Banking apps use for environment validation.
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin) - Monthly Android security patches. Track AccessibilityService and overlay permission changes.
- [SafetyNet Attestation (Deprecated)](https://developer.android.com/training/safetynet/attestation) - Predecessor to Play Integrity. Legacy banking apps may still reference.

---

## Educational Resources

### Projects

- [Takopii](https://github.com/F2u0a0d3/takopii) - **This project.** 4 banker specimens (0/75 VT), 107 detection rules, 10,400+ lines of analysis. Hub-and-spoke curriculum covering 17 real-world banker families.
- [learning-malware-analysis](https://github.com/RPISEC/Malware) - RPISEC Malware Analysis course materials. General malware fundamentals applicable to mobile.
- [android-security-awesome](https://github.com/nicholaschum/allsafe) - Curated list of Android security resources, tools, and papers.
- [Mobile Security Wiki](https://mobilesecuritywiki.com/) - Community wiki covering mobile security tools, techniques, and resources.

### Books

- *Android Security Internals* by Nikolay Elenkov - Deep-dive into Android security architecture relevant to understanding banker attack surfaces.
- *The Mobile Application Hacker's Handbook* by Dominic Chell et al. - Practical mobile security assessment methodology.
- *Android Hacker's Handbook* by Joshua Drake et al. - Technical reference for Android exploitation and defense.

### Courses and Labs

- [OWASP MSTG Hacking Playground](https://github.com/nicholaschum/allsafe) - Hands-on mobile security challenges aligned to MASTG.
- [HackTheBox Mobile Challenges](https://www.hackthebox.com/) - Android reversing and exploitation challenges in CTF format.

---

## Frida Script Collections

Public Frida scripts for SSL pinning bypass, root detection bypass, anti-instrumentation defeat, and defender-side monitoring.

### SSL Pinning Bypass

- [pcipolloni Universal SSL Pinning Bypass](https://codeshare.frida.re/@pcipolloni/universal-interception/) - Cross-library SSL pinning bypass covering OkHttp, HttpsURLConnection, TrustManager.
- [akabe1 frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/) - Modern multi-library unpinning script. Covers OkHttp3, Volley, Apache, TrustManagerImpl.
- [Q0120S Universal Root Detection And SSL Pinning Bypass](https://codeshare.frida.re/@Q0120S/) - Combined root + pinning bypass in single script.
- [objection android sslpinning disable](https://github.com/sensepost/objection) - Built-in objection command for automated pinning bypass.

### Root Detection Bypass

- [ub3rsick rootbeer-root-detection-bypass](https://codeshare.frida.re/@ub3rsick/rootbeer-root-detection-bypass/) - Hooks for the RootBeer library used by DVBank and many production banking apps.
- [Q0120S Universal Root Detection Bypass](https://codeshare.frida.re/@Q0120S/) - Broad root detection bypass covering multiple detection libraries.
- [objection android root disable](https://github.com/sensepost/objection) - Built-in objection command for root detection bypass.

### Anti-Instrumentation Defeat

- [okankurtuluss FridaBypassKit](https://github.com/nicholaschum/allsafe) - Anti-anti-Frida scripts. Defeats Frida-detection checks (default port scanning, /proc/self/maps inspection, known library path enumeration).
- frida-server port relocation -- Run `frida-server -l 0.0.0.0:1337` instead of default 27042 to defeat port-scanning Frida detection.
- frida-gadget library rename -- Build-time injection with renamed .so to defeat path-based Frida detection.

### Defender-Side Monitoring

- [Takopii Master Monitor](https://github.com/F2u0a0d3/takopii/tree/main/detection/frida) - 36-hook defender agent monitoring AccessibilityService dispatch, overlay creation, DGA computation, ATS gesture injection, clipboard access, DexClassLoader load, notification interception, SMS capture, evasion check execution.

---

## Contributing

Contributions are welcome. Priority areas:

1. **Threat intelligence links** -- Add reports on new 2026+ banker families as they are published.
2. **Tool additions** -- Open-source analysis tools relevant to banker malware that are not listed.
3. **RASP / MTD product coverage** -- Field-test results against banker specimens, documented in reproducible form.
4. **Frida scripts** -- New bypass or monitoring scripts tested against current banker techniques.
5. **Regional resources** -- Non-English threat intelligence and analysis resources (LatAm, APAC, EMEA).

To contribute: open a pull request adding your resource in the appropriate section. Include a one-line description. Ensure links are active and point to the canonical source. Vendor marketing pages are acceptable for commercial products; prefer technical documentation or GitHub repos where available.

---

## License

This list is part of the [Takopii](https://github.com/F2u0a0d3/takopii) project. Content is provided for educational and defensive research purposes.
