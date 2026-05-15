---
name: RASP Bypass Matrix Contribution
about: Submit RASP bypass field-test results for the bypass matrix
title: "[RASP] "
labels: rasp-bypass
assignees: ''
---

## Vendor Information

- **RASP vendor:** <!-- e.g., Talsec FreeRASP, Promon SHIELD, GuardSquare DexGuard -->
- **Vendor product version:** <!-- Exact version tested -->
- **Vendor tier:** <!-- Tier 1 (accessible) / Tier 2 (sales-gated) / Tier 3 (community) -->
- **License type used:** <!-- Free trial / open-source / evaluation / purchased -->

## Test Environment

- **Target APK:** <!-- Which specimen was wrapped? e.g., overlay-banker -->
- **Wrapping method:** <!-- CLI / Gradle plugin / cloud portal / manual integration -->
- **Test device:** <!-- e.g., Pixel 6 API 33, physical / emulator -->
- **Frida version:** <!-- e.g., 16.3.3 -->
- **frida-server configuration:** <!-- Default port or relocated? Gadget or server? -->
- **Root method:** <!-- Magisk + DenyList / KernelSU + Zygisk / emulator root -->

## Bypass Scripts Used

<!-- List the exact scripts from detection/frida/ or external sources applied. -->

| Script | Source | Purpose |
|---|---|---|
| <!-- e.g., evasion-bypass.js --> | <!-- detection/frida/ or URL --> | <!-- e.g., Anti-Frida defeat --> |
| | | |
| | | |

## Results Per Primitive

<!-- Fill in each row with the field-test outcome. -->
<!-- Legend: PASS = bypassed, PARTIAL = partially bypassed, BLOCKED = vendor blocked, N/T = not tested -->

| Primitive | Result | Notes |
|---|---|---|
| Frida attachment | <!-- PASS / BLOCKED --> | <!-- Did frida-server attach successfully? --> |
| Root detection bypass | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| SSL pinning bypass | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| Frida-detection bypass | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| Accessibility cross-app read | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| Overlay rendering (TYPE_APPLICATION_OVERLAY) | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| Overlay rendering (TYPE_ACCESSIBILITY_OVERLAY) | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| DexClassLoader hook | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| Reflection chain hook | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |
| Clipboard read hook | <!-- PASS / PARTIAL / BLOCKED / N/T --> | |

## Vendor Dashboard Observations

<!--
Did the vendor's dashboard/console detect the test activity?
What events appeared? What was missed?
Include time-to-detection if observable.
-->

## Responsible Disclosure Status

<!-- REQUIRED. RASP bypass contributions will not be merged without completed disclosure. -->

- [ ] Vendor notified (date: ___)
- [ ] Vendor contact method: <!-- e.g., security@vendor.com, HackerOne program -->
- [ ] Vendor acknowledged receipt (date: ___)
- [ ] 90-day disclosure window observed
- [ ] Vendor requested extension (details: ___)
- [ ] Vendor disputes finding (details: ___)
- [ ] Vendor patched (version: ___)
- [ ] First public disclosure (this is the first report)

## Distinctive Vendor Claims Tested

<!--
Per ANALYSIS.md section 10, each vendor makes specific claims.
Which claim did you test? Was it verified or refuted?
e.g., "Promon claims pre-launch detection -- verified/refuted because..."
-->

## Matrix Row Data

<!--
Provide the formatted row for benchmarks/rasp_bypass_matrix.md.
Use the legend: check = bypassed, half = partial, cross = blocked, ? = not tested
-->

```
| <Vendor> <Version> | <SSL> | <Root> | <Frida> | <A11y> | <Overlay> | <DCL> | <Reflection> | <Clipboard> |
```

## Additional Context

<!-- Anomalies observed, vendor-specific behaviors, suggestions for further testing. -->
