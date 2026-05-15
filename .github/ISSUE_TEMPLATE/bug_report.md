---
name: Bug Report
about: Report a bug in a specimen, detection rule, safety mechanism, or tooling
title: "[BUG] "
labels: bug
assignees: ''
---

## Specimen / Component

<!-- Which specimen or component is affected? -->

- [ ] sms-stealer
- [ ] overlay-banker
- [ ] dropper
- [ ] stage-1-evasion
- [ ] stage-2-payload
- [ ] Detection rules (YARA / Sigma / Frida)
- [ ] Analyst tooling (scripts/)
- [ ] Safety mechanism (LabGate / Telemetry / Consent)
- [ ] Documentation
- [ ] Build system
- [ ] Other: ___

## Build Environment

- **OS:** <!-- e.g., Ubuntu 22.04, macOS 14, Windows 11 -->
- **JDK version:** <!-- e.g., OpenJDK 17.0.10 -->
- **Kotlin version:** <!-- e.g., 2.1.21 -->
- **AGP version:** <!-- e.g., 8.5.0 -->
- **Android target device/emulator:** <!-- e.g., Pixel 7 API 34, emulator API 30 Google APIs -->
- **Frida version (if applicable):** <!-- e.g., 16.3.3 -->
- **Takopii version/commit:** <!-- e.g., v0.2.0-pre or commit SHA -->

## Expected Behavior

<!-- What should happen? Be specific. -->

## Actual Behavior

<!-- What happens instead? Include error messages, stack traces, or unexpected output. -->

## Steps to Reproduce

<!--
Numbered steps. Minimal reproduction path.
Include exact commands, configuration, and specimen used.
-->

1.
2.
3.

## Detection Rule Context (if applicable)

<!--
If the bug is in a detection rule, provide:
- Rule name and file path
- Target APK/specimen tested against
- Expected rule hits vs actual
- False positive details (if FP bug)
-->

## Safety Mechanism Context (if applicable)

<!--
If the bug is in a safety mechanism (LabGate, Telemetry, Consent):
- Which gate is affected?
- Does the bug weaken safety (stealer code executes when it should not)?
- Does the bug over-restrict (stealer code blocked when all gates should pass)?
- Include relevant telemetry.log lines if available.
-->

## Logs / Output

```
<!-- Paste relevant logs, build output, or error traces here. -->
```

## Additional Context

<!-- Screenshots, related issues, or anything else relevant. -->
