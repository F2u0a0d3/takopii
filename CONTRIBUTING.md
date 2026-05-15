# Contributing to Takopii

Takopii is a community-driven Android banker-malware education framework. Contributions strengthen the detection corpus, expand family coverage, and populate the RASP bypass matrix. This document covers how to contribute and what constraints apply.

---

## How to Contribute

1. **Fork** the repository.
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b contribution/your-feature-name
   ```
3. **Make your changes** following the conventions below.
4. **Test** your contribution against the specimen set.
5. **Open a Pull Request** against `main` using the PR template at the bottom of this document.

Small, focused PRs are preferred. One detection rule per PR, one family addition per PR, one matrix row per PR.

---

## Priority Contribution Areas

### 1. RASP Bypass Matrix Population

The highest-value contribution. Field-test commercial RASP products against the specimens and report structured results.

- Wrap a specimen using the vendor's tooling (CLI / Gradle plugin / cloud portal).
- Apply the public Frida script set from `detection/frida/` to the wrapped specimen.
- Document results per script category: attach success, hook application, vendor detection/block/miss, dashboard output, time-to-detection.
- Submit via the RASP Bypass issue template.
- **Responsible disclosure is mandatory** -- see protocol below.

Tier-1 vendors (Talsec FreeRASP, DoveRunner/AppSealing, Build38/OneSpan) are the immediate priority. Tier-2 and Tier-3 vendor results are welcome as community contributions.

### 2. Detection Rule Improvements

- Reduce false-positive rates on existing YARA/Sigma/Frida rules.
- Add new behavioral patterns from emerging banker families.
- Improve rule metadata (MITRE ATT&CK IDs, MASTG control IDs, false-positive notes).
- Validate rules against known-good app corpora.

### 3. New Family Coverage

- Add techniques from documented 2026+ banker families using public threat-intel sources only.
- Each new technique requires: specimen code, matching detection rule, spoke documentation.
- Source every claim from a public report (Cleafy, ThreatFabric, Zscaler, ESET, NCC Group, Lookout, Zimperium, bin.re).

### 4. Translation

- Non-English documentation for LatAm (Portuguese, Spanish) and APAC regions.
- Translate spoke companions and workflow docs. Hub document (`ANALYSIS.md`) translation is lower priority.

### 5. Analyst Tooling

- Improvements to `scripts/analyst-tools/` scripts.
- New workflow recipes for `docs/`.
- MobSF custom rule integration enhancements.

---

## Code Conventions

### Language and Runtime

- **Kotlin 2.1.21+**, JVM toolchain 17. No Java unless JNI interop forces it.
- **Coroutines**: structured, scoped to lifecycle. No GlobalScope.
- **HTTP**: OkHttp with cert pinning enforced even on lab loopback.
- **DI**: manual constructor injection. No Hilt/Koin in lab overlay.
- **Async**: `suspend fun` over callbacks.
- **Error handling**: typed `Result<T>` over thrown exceptions for cross-module calls.
- **Time**: no `System.currentTimeMillis()` or `Date()`. Inject `kotlin.time.Clock`.
- **Serialization**: `@Serializable` save classes have `schemaVersion: Int`.

### Lab Gate Enforcement

Every stealer code path must be gated by `LabGate.shouldExecuteStealerPath()` as an early-return guard. All four gates are immutable:

```kotlin
fun shouldExecuteStealerPath(): Boolean {
    // GATE 1: BuildConfig.LAB_BUILD == true
    // GATE 2: SharedPreferences("takopii.consent.acknowledged") == true
    // GATE 3: C2 URL host resolves to RFC1918 / loopback
    // GATE 4: /sdcard/Android/data/io.takopii/files/.lab_marker exists
    return gate1 && gate2 && gate3 && gate4
}
```

Do not weaken, skip, bypass, or propose alternate implementations of any gate.

### Telemetry

Every sensitive operation must emit a telemetry line via `Telemetry.event(module, name, vararg pairs)`. No silent operations. This includes: Accessibility events, notification reads, SMS reads, clipboard reads, overlay draws, network sends, DexClassLoader fetches.

### Source Set Isolation

- Stealer code belongs in `src/lab/kotlin/io/takopii/` only.
- Never place stealer code in `src/main/`.

### Test Coverage

- 80%+ test coverage on `safety/*` package.
- Detection rules must pass false-positive tests against known-good corpus.

---

## Detection Rule Contribution Requirements

Every detection rule submission must include:

### YARA Rules

```yara
rule Takopii_YourRuleName {
    meta:
        author      = "Your Name"
        description = "What this rule catches"
        reference   = "Public threat-intel report URL"
        family      = "Banker family name"
        mitre       = "T1XXX / T1XXX.YYY"
        mastg       = "MASTG-CTRL-XX"
        maswe       = "MASWE-XXXX"
        fp_notes    = "Known false-positive scenarios and mitigations"
        date        = "YYYY-MM-DD"
    strings:
        // ...
    condition:
        // ...
}
```

### Sigma Rules

```yaml
title: Takopii - Your Rule Name
id: <UUID>
status: experimental
description: What this rule catches
author: Your Name
date: YYYY-MM-DD
references:
    - https://public-threat-intel-report-url
tags:
    - attack.tXXXX
    - attack.mobile
logsource:
    product: android
    service: logcat
detection:
    selection:
        # ...
    condition: selection
falsepositives:
    - Known false-positive scenarios
level: medium
```

### Frida Monitor Modules

```javascript
// Module: your-module-name
// Target: Class.method being hooked
// Family: Banker family reference
// MITRE: T1XXX
// Author: Your Name

Java.perform(function() {
    // Hook implementation
    // Must emit structured output via send()
});
```

### Validation Requirements

All detection rules must be tested against:

1. **Known-bad corpus** -- the Takopii specimen set. Rule must trigger on at least one specimen.
2. **Known-good corpus** -- a set of legitimate apps. Rule must NOT trigger false positives.
3. Document the test results in your PR.

---

## Responsible Disclosure Protocol for RASP Vendor Testing

RASP bypass results are the most sensitive contribution type. Follow this protocol without exception.

### Before Publication

1. **Notify the vendor 90 days before publication.** Use the vendor's published security contact.
2. **Share methodology, not exploit code.** Describe what category of bypass succeeded, not the exact script chain.
3. **Document the notification** in your PR -- date sent, vendor contact used, acknowledgment received.
4. **Coordinate timing** with the vendor if they request a delay for patching.

### During Testing

- Test only on devices and apps you own or have written authorization to instrument.
- Use DVBank or Takopii specimens as the target. Never wrap production banking apps.
- Do not circumvent vendor license terms. Use free/trial tiers where available.

### In the Matrix Row

- Record outcome per script category: bypassed / partial / blocked / not tested.
- Include vendor version tested.
- Link to responsible-disclosure notification.
- Do not publish per-vendor exploit recipes. Methodology only.

### Vendor Response

- If the vendor disputes a finding, document the dispute in the matrix cell.
- If the vendor patches the gap, update the matrix cell with the fixed version.
- If the vendor requests more than 90 days, accommodate reasonable requests.

---

## Community Guidelines

### Prohibited Content

The following will not be accepted in any PR:

- **Real-target overlays** -- no HTML/XML mimicking real bank login pages.
- **Real institution names** -- no bank names, financial institution identifiers, or branded assets.
- **Real OTP patterns** -- no regex specific to any institution's OTP format.
- **Distributable APK build scripts** -- no signing configurations for Play Store or public distribution.
- **Public C2 endpoints** -- all network code must validate RFC1918/loopback only.
- **Code that bypasses LabGates** -- any PR weakening gate enforcement will be rejected.
- **Content without matching detection** -- every new attack technique must ship with a detection rule.

### Expected Conduct

- Source every analytical claim from a public report. No unattributed assertions.
- Security-community professional tone. Expert audience assumed.
- No "educational disclaimer" boilerplate -- `SAFETY.md` is the disclaimer.
- No closing offers, "let me know if," or "hope this helps."

### Licensing

Contributions are accepted under the same research license as the project. By submitting a PR, you agree that your contribution may be distributed under that license.

---

## Pull Request Template

Use this template when opening a PR. Copy it into the PR description.

```markdown
## Summary

<!-- 1-3 sentences. What does this PR add or change? -->

## Category

<!-- Check one -->
- [ ] Detection rule (YARA / Sigma / Frida)
- [ ] RASP bypass matrix row
- [ ] New family technique
- [ ] Specimen code
- [ ] Documentation / spoke
- [ ] Analyst tooling
- [ ] Translation
- [ ] Bug fix
- [ ] Other: ___

## Checklist

- [ ] Lab gates enforced on all stealer code paths
- [ ] Telemetry emitted on all sensitive operations
- [ ] No real-target overlays, institution names, or OTP patterns
- [ ] C2 endpoints validate RFC1918/loopback only
- [ ] Detection rule included (if adding attack technique)
- [ ] Detection rule tested against known-good corpus (no false positives)
- [ ] Detection rule tested against specimen set (triggers expected hits)
- [ ] Source set isolation respected (lab code in src/lab/ only)
- [ ] Responsible disclosure completed (if RASP bypass)
- [ ] Public threat-intel source cited for all claims

## Test Results

<!-- How did you validate this change? -->

## References

<!-- Public threat-intel reports, MITRE IDs, MASTG controls -->
```

---

## Questions

Open a GitHub Discussion for questions about:
- Contribution scope or priority
- Detection rule design
- RASP testing methodology
- Family attribution
- Spoke template interpretation

File issues for bugs, not questions.
