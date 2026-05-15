# Security Policy

## What Takopii Is

Takopii is an **educational specimen framework** for Android banker-malware analysis. It contains production-grade banker malware architecture -- techniques sourced from 17 documented real-world families -- paired with matching detection rules. Every specimen is lab-constrained at the code level.

The architecture is production-grade. The constraints are code-level, not configuration-level. This distinction matters: removing the constraints requires source modification and recompilation, not a config toggle.

---

## Safety Mechanism: The Four LabGates

All stealer code paths are gated by `LabGate.shouldExecuteStealerPath()`, which returns `true` only when **all four** conditions hold simultaneously. If any gate fails, stealer code returns immediately. The app behaves as a plain specimen with no offensive capability.

### Gate 1: Lab Build Flag

```
BuildConfig.LAB_BUILD == true
```

Set only by the Gradle product flavor `lab`. Production flavor compiles with `LAB_BUILD = false`, making stealer code permanently dead in production builds.

### Gate 2: Explicit Consent

```
SharedPreferences("takopii.consent.acknowledged") == true
```

Set only after the user completes a 6-screen first-launch consent dialog. Each screen names the runtime capability about to be activated. The user must tap through all six screens -- partial completion leaves the gate closed.

### Gate 3: RFC1918 / Loopback Network

```
C2 URL host resolves to RFC1918 or loopback address
```

Validation in `C2Client.kt` requires every network destination to match: `127.0.0.1`, `10.0.2.2` (emulator host loopback), `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`. Public IP addresses are refused at dispatch. This is hardcoded, not configurable. DGA output is also constrained to RFC1918 in `DomainGenerator.kt`.

### Gate 4: Lab Marker File

```
/sdcard/Android/data/io.takopii/files/.lab_marker exists
```

The operator must manually `adb push` this marker file before activating lab mode. The app cannot create this file itself. It is removed on uninstall.

---

## What Ships in This Repository

| Artifact | Ships | Distribution |
|---|---|---|
| Lab specimen source code | Yes | Public repository |
| Detection rules (YARA, Sigma, Frida) | Yes | Public repository |
| Analyst tooling scripts | Yes | Public repository |
| Spoke documentation (techniques/) | Yes | Public repository |
| Research briefs (threat-intel citations) | Yes | Public repository |
| Lab C2 server (Python, loopback-only) | Yes | Public repository |
| Workflow docs and case studies | Yes | Public repository |

## What Does NOT Ship

| Artifact | Status |
|---|---|
| Real C2 infrastructure | Not included |
| Real bank login overlay templates | Not included |
| Real OTP patterns specific to any institution | Not included |
| Real institution names or branded assets | Not included |
| Production signing keys | Not included |
| Play Store build configurations | Not included |

---

## Reporting Security Issues

Takopii handles three categories of security reports differently.

### Category A: Bugs in Safety Mechanisms

**What:** Flaws in LabGate enforcement, telemetry gaps, source-set isolation failures, or any path that allows stealer code to execute without all four gates passing.

**Where to report:** Open a public GitHub issue using the Bug Report template. Safety mechanism bugs benefit from public visibility -- the entire community should know about and verify fixes.

**What to include:**
- Which gate is affected
- Reproduction steps
- Proposed fix (if you have one)

### Category B: RASP Vendor Gaps

**What:** Bypass results discovered through responsible RASP testing methodology.

**Where to report:** Open a public GitHub issue using the RASP Bypass template, but only **after** completing the 90-day responsible disclosure protocol with the affected vendor. See `CONTRIBUTING.md` for the full protocol.

**What to include:**
- Vendor name and version tested
- Category of bypass (not exact exploit script)
- Responsible disclosure timeline and vendor acknowledgment
- Matrix row data

### Category C: Weaponization Concerns

**What:** Discovery of a method to weaponize Takopii specimens against real users, a hostile fork distributing specimens as malware, or any scenario where Takopii material causes harm to real targets.

**Where to report:** Do not open a public issue. Contact the maintainer privately:
- **GitHub:** Send a private vulnerability report via GitHub's Security Advisories tab (Repository > Security > Advisories > New draft security advisory)
- **Email:** Use the contact in the repository owner's GitHub profile

**What to include:**
- Description of the weaponization path
- Evidence (fork URL, distribution vector, affected users if known)
- Suggested mitigation

**Response timeline:** Acknowledgment within 72 hours. Triage within 7 days. For active distribution of hostile forks, escalation to GitHub Trust & Safety is immediate.

---

## Threat Model

### What Takopii Defends Against

| Threat | Defense |
|---|---|
| Accidental production build with stealer code | Source-set isolation. Production flavor cannot see lab classes at compile time. |
| Lab APK sideloaded to consumer device | 6-screen consent dialog + manual marker file requirement. Both must be completed deliberately. |
| Specimen escapes test device, runs on victim phone | All four gates required. Without `.lab_marker` and consent, stealer code never executes. |
| Stealer capability used without detection awareness | Every attack technique ships with matching detection rules. Pedagogy enforces paired learning. |

### What Takopii Does NOT Defend Against

| Threat | Status |
|---|---|
| Hostile fork that removes LabGates and ships pure stealer | Cannot prevent. Mitigated by: license terms, public attribution, detection rules that catch the techniques regardless of packaging. |
| Unauthorized testing on devices the operator does not own | Operator responsibility. Consent ceremony documents this obligation. |
| Use in jurisdictions restricting mobile-malware research | Operator responsibility. |

### Design Principle

Safety constraints are **code-level** -- loopback C2, own-package AccessibilityService filters, no SMS-receiving manifest declaration, no cross-app screenshot capability. These are not flags that can be toggled. Removing them requires modifying source, recompiling, and re-signing. The architecture is production-grade; the constraints are structural.

---

## C2 Network Boundary

All C2 communication is restricted to RFC1918 and loopback addresses. This is enforced in two locations:

1. **`C2Client.kt`** -- validates every outbound host before dispatch. Public IP = refused.
2. **`DomainGenerator.kt`** -- DGA output constrained to RFC1918 address space.

There is no configuration, environment variable, or runtime flag that relaxes this restriction. The only path to public-IP exfiltration is source modification + recompilation.

---

## Supported Versions

| Version | Security Updates |
|---|---|
| Latest release | Yes |
| Previous release | Best-effort |
| Older releases | No |

Report issues against the latest release. If you discover a safety mechanism bug in an older version that persists in the latest, report against the latest.

---

## Acknowledgments

Security researchers who identify and report LabGate improvements, detection-rule gaps, or responsible RASP bypass findings will be credited in the CHANGELOG and (with consent) in conference presentations.
