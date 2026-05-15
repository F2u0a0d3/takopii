---
name: Detection Rule Contribution
about: Propose a new or improved YARA, Sigma, or Frida detection rule
title: "[DETECTION] "
labels: detection-rule
assignees: ''
---

## Rule Type

- [ ] YARA (static APK/DEX scanning)
- [ ] Sigma (runtime behavioral detection)
- [ ] Frida monitor module (dynamic instrumentation)

## Contribution Type

- [ ] New rule
- [ ] Improvement to existing rule (reduce FP / increase coverage)
- [ ] False-positive fix
- [ ] Rule retirement (rule no longer catches current variants)

## Target Technique

- **Technique name:** <!-- e.g., DGA domain rotation, overlay credential capture -->
- **MITRE ATT&CK Mobile ID:** <!-- e.g., T1437.001 -->
- **MASTG control ID:** <!-- e.g., MASTG-CTRL-XX -->
- **MASWE ID (if applicable):** <!-- e.g., MASWE-XXXX -->
- **Banker family reference:** <!-- e.g., SharkBot V2.8, Anatsa V4 -->
- **Public threat-intel source:** <!-- URL to the report this is based on -->

## Rule Content

```
<!-- Paste the full rule here (YARA / Sigma YAML / Frida JS). -->
<!-- Include all required metadata fields per CONTRIBUTING.md. -->
```

## Specimen Coverage

<!-- Which Takopii specimens does this rule trigger on? -->

| Specimen | Expected Hit | Verified |
|---|---|---|
| sms-stealer | Yes / No | Yes / No |
| overlay-banker | Yes / No | Yes / No |
| dropper | Yes / No | Yes / No |
| stage-1-evasion | Yes / No | Yes / No |

## False-Positive Testing

<!-- Required for all rule contributions. -->

- **Known-good apps tested against:** <!-- e.g., "10 top-100 Play Store apps" or specific app list -->
- **False positives found:** <!-- None / list any triggers on legitimate apps -->
- **Mitigation applied:** <!-- How FPs were suppressed without losing real-banker coverage -->

## Detection Gap This Addresses

<!--
What gap in the current detection corpus does this rule fill?
Is there an existing rule this replaces or supplements?
Link to the relevant spoke in techniques/ if applicable.
-->

## Bypass Awareness

<!--
What evasion techniques could defeat this rule?
Are bypass variants documented in the relevant spoke?
Does a paired rule exist that catches the bypass?
-->

## Test Methodology

<!--
How did you validate this rule?
- Static: yara command + specimen path + output
- Sigma: log source + event stream used
- Frida: target app + hook attachment method + observed output
-->

```
<!-- Paste test commands and output here. -->
```

## Additional Context

<!-- Related rules, alternative approaches considered, references. -->
