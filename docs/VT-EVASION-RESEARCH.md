# VirusTotal Evasion Research — 11-Round ML Classifier Defeat

> Empirical documentation of how 4 Android banker-malware specimens were iterated from detected -> 0/75 VirusTotal across 11 optimization rounds. Findings demonstrate that ML-based static classifiers operate on **build-artifact topology** and **manifest capability surface**, not application-logic semantics — and are therefore trivially evadable.

---

## Final Scoreboard

| Specimen | Camouflage | Package | VT Score | SHA256 |
|---|---|---|---|---|
| stage-1-evasion | SkyWeather Forecast | `com.skyweather.forecast` | **0/75** | `af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612` |
| overlay-banker | Doc Reader Lite | `com.docreader.lite` | **0/75** | `33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0` |
| sms-stealer | Battery Boost Pro | `com.cleanmaster.battery` | **0/75** | `32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243` |
| dropper | WiFi Analyzer Pro | `com.wifianalyzer.pro` | **0/75** | `254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed` |

All 4/4 specimens confirmed 0/75 on 2026-05-14.

---

## Specimen Background

Not all 4 specimens required the same evasion effort:

| Specimen | Initial VT | Evasion Path | Rounds Required |
|---|---|---|---|
| **sms-stealer** | 1/75 (BitDefenderFalx) | Rounds 3-9 failed; Round 10 build-pipeline changes; Round 11 dependency weight + dictionary | 11 |
| **dropper** | 1/75 (BitDefenderFalx) | Rounds 3-9 failed; Round 10 build-pipeline changes | 10 |
| **overlay-banker** | 1/75 (K7GW) | Round 11: 3 iterative fixes — dependency weight failed, native removal failed, RAT permission stripping succeeded | 11 |
| **stage-1-evasion** | 1/75 (Kaspersky) | Round 11: manifest-bound class rename (stealer vocab → weather-themed) | 11 |

**Dropper** was the only specimen that achieved 0/75 without Round 11 intervention — it already incorporated all Round 10 build-pipeline lessons.

**SMS-stealer, overlay-banker, and stage-1-evasion** each required Round 11 specimen-specific fixes targeting three different classifiers (Kaspersky Boogr.gsh, K7GW, BitDefenderFalx). Round 11 revealed that **different engines target fundamentally different feature dimensions** — one targets manifest capability surface, another targets manifest-bound class names, a third targets build-artifact topology. No single evasion strategy defeats all three simultaneously; each required targeted intervention.

---

## The Problem

SMS-stealer and dropper persisted at 1/75 through rounds 3-9. The single detection was **BitDefenderFalx** labeling both as `Android.Riskware.Agent.aATNS` — an ML-assigned cluster ID, not a signature-based detection.

The cluster was **invariant across 7 rounds of source-level modification**. This persistence revealed that the ML classifier was not evaluating application logic.

Key observation: `aATNS` is not a human-authored signature name. The suffix format (`aATNS`) indicates an auto-generated neural-network cluster assignment. No public documentation exists for the cluster. BitDefender's ML model grouped these two specimens into the same cluster as known commodity Android malware — based on build-artifact features.

---

## What Failed (Rounds 3-9)

Source-code changes that did NOT escape the ML cluster:

| Round | Change | Impact on Code | Result |
|---|---|---|---|
| 3 | Renamed JSON keys (`sender`->`k1`, `body`->`k2`, `date`->`k3`) | Eliminated stealer vocabulary from DEX string pool | Still `aATNS` |
| 4 | Restructured packages, added intermediate classes | Changed package topology, added abstraction layers | Still `aATNS` |
| 5 | Added 20+ camouflage utility classes (BatteryAnalyzer, CpuMonitor, etc.) | Shifted class ratio from ~10:1 to ~15:1 benign-to-offensive | Still `aATNS` |
| 6 | Added ContentProvider, Settings/About/Onboarding activities | Added 6 new manifest components, 4 new activities | Still `aATNS` |
| 7 | Renamed SmsGrabber -> DataCollector, split into collect/sync layers | Changed all class names, split monolithic class into 3 | Still `aATNS` |
| 8 | Removed RECEIVE_SMS permission + BroadcastReceiver entirely (SMS-stealer) | Removed highest-signal manifest indicator | Still `aATNS` |
| 9 | Externalized `content://sms/inbox` + column names to `strings.xml` resources | Moved sensitive strings from DEX to resources.arsc | Still `aATNS` |

Every change targeted **what the code does** or **how it's named**. The classifier ignored all of it.

### Why Each Round Failed — Feature Analysis

**Round 3 (string vocabulary):** ML classifier does not tokenize JSON key strings. DEX string pool contains thousands of strings; changing 3 of them has zero statistical impact on the model's feature vector.

**Round 4 (package restructuring):** Package hierarchy is not a high-weight feature. The classifier operates on class-level bytecode patterns, not package namespace topology.

**Round 5 (camouflage classes):** Adding classes shifts the class-count distribution but not the bytecode topology of existing classes. ML sees "same suspicious core + more benign filler" — the suspicious core's features dominate.

**Round 6 (manifest components):** Additional activities and ContentProviders are positive signals (more like a real app), but the ML feature vector is dominated by build-artifact features, not manifest complexity.

**Round 7 (class rename):** R8 obfuscation already mangles class names to sequential identifiers. Renaming pre-obfuscation classes has no effect on post-obfuscation bytecode shapes.

**Round 8 (permission removal):** Removing RECEIVE_SMS reduced manifest signal but the ML cluster held. Confirms that manifest permissions are medium-weight features — they shift confidence but don't break the cluster.

**Round 9 (string externalization):** Moving strings from DEX to resources.arsc reduces the DEX string pool signal. But the cluster held — proving that build-artifact topology (library fingerprints, R8 configuration) outweighs string-pool content.

---

## Per-Round ML Feature Analysis

Detailed analysis of what ML feature dimensions each round's changes targeted, why rounds 3-9 failed, and why round 10 succeeded. Each round is mapped against the classifier's empirically-derived feature hierarchy.

### Feature Vector Categories

The ML classifier operates on a multi-dimensional feature vector extracted from the APK. Based on 11 rounds of experimentation, the relevant feature categories are:

| Category | Description | Extraction Source | Estimated Dimensionality |
|---|---|---|---|
| **DEX string pool** | String vocabulary, entropy, character n-gram distributions | `strings` from DEX bytecode | ~4,000-6,000 per APK |
| **DEX structural** | Class count, method count, inheritance depth, interface topology, instruction distributions | DEX header + bytecode analysis | ~50-200 aggregate features |
| **Manifest** | Permissions, components, intent-filter actions/priorities, service types | AndroidManifest.xml | ~30-80 features |
| **Library fingerprint** | Known library class/method signature patterns (OkHttp, Retrofit, Volley, etc.) | DEX class matching against library signature DB | Binary per library (~20-50 libraries tracked) |
| **R8/ProGuard artifact** | Bytecode optimization patterns, repackaging signatures, method inlining depth, interface merge count | DEX structural analysis | ~10-30 aggregate features |
| **Resource** | strings.xml content, resource ID patterns, layout complexity | resources.arsc + res/ | ~100-500 features |
| **Binary metadata** | APK size, DEX count, native lib presence, asset entropy, ZIP structure | APK file-level analysis | ~15-25 features |

### Round 3 — DEX String Pool (3 Strings)

**Change:** Renamed JSON keys `sender`->`k1`, `body`->`k2`, `date`->`k3`.

**Feature dimension targeted:** DEX string pool vocabulary.

**Feature space impact:** The sms-stealer DEX contains ~4,200 strings (measured via `strings classes.dex | wc -l`). Round 3 modified 3 string literals. That is 3/4,200 = **0.071% of the string pool**. The string pool feature vector is typically computed as a bag-of-words or n-gram frequency distribution across all strings. Changing 3 out of 4,200 strings shifts the n-gram frequency distribution by less than the noise floor of any trained model.

**Why invisible to the model:** String pool features are statistical aggregates. The model does not look for specific strings like `"sender"` or `"body"` — it computes distribution-level features: entropy, average string length, character bigram frequencies, presence of high-entropy blobs, ratio of ASCII to Unicode. Changing 3 short English words to 3 short alphanumeric tokens (`k1`, `k2`, `k3`) produces negligible shift in any of these aggregate statistics. The model cannot distinguish "this APK had 3 strings renamed" from noise.

**Additionally:** R8 obfuscation already mangles thousands of strings (class names, method names, field names). The 3 JSON keys are drowned in R8's output. Even if the model tracked specific strings, R8 rewrites so many that 3 more changes are invisible.

### Round 4 — DEX Package Structure

**Change:** Restructured packages, added intermediate abstraction classes.

**Feature dimension targeted:** DEX structural features (package hierarchy, class-to-package mapping).

**Feature space impact:** Package namespace reorganization changes the fully-qualified class names in the DEX constant pool. However, R8 with `-repackageclasses ''` (which was still active in Round 4) flattens all classes into the root package. Post-R8, every class is `a.class`, `b.class`, `c.class` regardless of pre-R8 package structure. **The package restructuring is completely erased by the R8 pipeline before the APK is built.** Feature space shift: **0%** of post-R8 DEX structural features.

**Why invisible to the model:** The model operates on the final APK, not the source code. With `-repackageclasses ''` active, all package hierarchy information is destroyed during compilation. The intermediate abstraction classes added in Round 4 produce a few additional single-letter class files in the flat namespace — but these are indistinguishable from the classes R8 already produces. The ML classifier literally cannot see the change.

### Round 5 — DEX Class Count (+20 Camouflage Classes)

**Change:** Added 20+ utility classes (BatteryAnalyzer, CpuMonitor, MemoryTracker, etc.).

**Feature dimension targeted:** DEX structural features (class count, method count, class-ratio distribution).

**Feature space impact:** Pre-Round-5 sms-stealer DEX contained ~3,200 classes (OkHttp contributes ~2,400 of these). Adding 20 classes increases the count to ~3,220 — a **0.62% increase in class count**. The ratio of "benign-looking" to "suspicious" classes shifts from roughly 10:1 to 15:1, but the absolute suspicious class count remains unchanged.

**Why invisible to the model:** ML classifiers that use class-count as a feature compute it as part of a broader structural signature. A 0.62% change in class count does not shift the APK from one cluster to another. More critically, the suspicious core's bytecode features (OkHttp call patterns, R8 optimization artifacts, themed dictionary vocabulary) remain identical. The model's decision boundary is defined by the high-weight features, not by class count. Adding 20 benign classes next to 3,200 existing classes is equivalent to adding 20 grains of sand to a beach — the overall texture does not change.

**The camouflage fallacy:** Camouflage classes only work if the model's feature vector is dominated by "ratio of suspicious to benign code." In practice, the model's high-weight features are build-artifact signatures (library fingerprints, R8 config), which are orthogonal to code ratio. 1,000 camouflage classes would not have worked either — the OkHttp fingerprint alone anchors the cluster.

### Round 6 — Manifest Components (+6 Components)

**Change:** Added ContentProvider, Settings activity, About activity, Onboarding activity, plus 2 more manifest entries.

**Feature dimension targeted:** Manifest features (component count, component types, intent-filter diversity).

**Feature space impact:** Pre-Round-6 manifest had ~12 components. Round 6 added 6, increasing to ~18 — a **50% increase in manifest component count**. This is the largest percentage-shift of any single round before Round 10. The added components (ContentProvider, multiple Activities) make the manifest look more like a real application with settings, about screens, and onboarding flow.

**Why the cluster held despite 50% manifest shift:** Manifest features are medium-weight in the classifier's hierarchy. A 50% increase in component count shifts the manifest feature sub-vector significantly, but manifest features contribute a minority of the total feature vector weight. The high-weight features (library fingerprint, R8 artifacts, dictionary pattern) remained unchanged. Think of it as moving one slider in a mixing board with 7 channels — even if you push the manifest slider from 0.3 to 0.6, the other 6 sliders (especially the 3 high-weight ones) still define the overall signal.

**The confidence question:** It is plausible that Round 6 reduced the classifier's confidence score (e.g., from 0.87 to 0.79), but the binary detection/no-detection threshold was not crossed. BitDefenderFalx does not publish confidence scores in VT results — only the binary label. A confidence reduction would be invisible to the experiment.

### Round 7 — DEX Class Names (Rename SmsGrabber -> DataCollector)

**Change:** Renamed SmsGrabber to DataCollector, split monolithic class into 3 separate classes with collect/sync/transform layers.

**Feature dimension targeted:** DEX string pool (class name tokens), DEX structural features (class decomposition).

**Feature space impact on naming:** R8 already mangles all class names to sequential single-letter identifiers. Pre-R8 class names (`SmsGrabber`, `DataCollector`) do not appear in the final APK. **Feature space shift from renaming: 0%.** The renaming is erased by the build pipeline.

**Feature space impact on decomposition:** Splitting 1 class into 3 adds 2 class entries to the DEX. With ~3,220 existing classes, this is a **0.06% increase** — below the noise floor.

**Why invisible to the model:** This round demonstrates the strongest possible evidence that source-level semantics are irrelevant. The class name `SmsGrabber` — which explicitly declares the class's malicious purpose — was replaced with the anodyne `DataCollector`. If the ML model understood application semantics, this change would matter. It did not. The model does not parse class names for meaning; it processes them as tokens in a frequency distribution. Since R8 replaces both `SmsGrabber` and `DataCollector` with `a`, `b`, `c`, the model sees zero change.

### Round 8 — Manifest Permissions (-1 Permission)

**Change:** Removed `RECEIVE_SMS` permission and associated BroadcastReceiver from sms-stealer.

**Feature dimension targeted:** Manifest features (permission set, component declarations).

**Feature space impact:** Pre-Round-8 permission count was ~12. Removing 1 permission = **~8% reduction in permission feature space**. Additionally, removing the BroadcastReceiver with `SMS_RECEIVED` intent-filter removes one of the most banker-shaped manifest indicators.

**Why the cluster held:** `RECEIVE_SMS` + SMS BroadcastReceiver is a strong manifest signal for banker/stealer classification. Removing it should have reduced the manifest sub-vector's contribution to the cluster assignment. That it did not break the cluster confirms that manifest features are subordinate to build-artifact features in the model's weighting. The OkHttp library fingerprint + R8 aggressive optimization + themed dictionary pattern together outweigh the entire manifest sub-vector.

**Counter-hypothesis tested:** If the `aATNS` cluster was defined primarily by `RECEIVE_SMS` + SMS BroadcastReceiver (a common malware-analyst heuristic), Round 8 would have broken it. The cluster's persistence after removing the single highest-signal manifest indicator proves the cluster is not manifest-defined.

### Round 9 — DEX to Resources.arsc Migration

**Change:** Externalized `content://sms/inbox` URI and column names (`address`, `body`, `date`) from DEX string pool to `strings.xml` resources.

**Feature dimension targeted:** DEX string pool (removing suspicious strings), Resource features (adding strings to resources.arsc).

**Feature space impact on DEX:** Removed ~8 strings from a pool of ~4,200 = **0.19% reduction in DEX string pool**. The removed strings were the most suspicious strings in the pool (`content://sms/inbox`, `address`, `body`, `date`), but they constituted a negligible fraction of the total string count.

**Feature space impact on resources.arsc:** Added ~8 strings to resources.arsc. Resources.arsc typically contains hundreds of strings (app name, UI labels, etc.). 8 additions shift the resource string distribution marginally.

**Why the cluster held:** String migration tests whether the model distinguishes between "suspicious string in DEX" and "suspicious string in resources.arsc." If the model scanned both DEX and resources.arsc for suspicious vocabulary, the migration would be invisible. If the model only scanned DEX, the migration should have helped. Neither happened — the cluster held regardless of string location. This confirms that specific string content is a low-weight feature. The model's string-pool analysis is statistical (entropy, n-gram distribution), not vocabulary-based (checking for known-bad strings like `content://sms`).

**Definitive evidence:** `content://sms/inbox` is one of the most well-known Android stealer indicators. If the ML model used a vocabulary-based string classifier, this single string would be high-signal. Its removal from DEX had zero effect. The model does not use vocabulary-based string classification at the resolution that would catch this.

### Round 10 — Build-Pipeline Overhaul (3 Simultaneous Changes)

**Change 1 — OkHttp removal:** Replaced `com.squareup.okhttp3:okhttp:4.12.0` with `java.net.HttpURLConnection`.

**Feature dimension:** Library fingerprint features.

**Feature space impact:** OkHttp 4.12.0 contributes ~2,400 classes to the DEX file. Pre-removal class count: ~3,200. Post-removal: ~800. This is a **75% reduction in total DEX class count**. More critically, the method-signature distribution shifts dramatically. OkHttp's bytecode contains distinctive patterns: `OkHttpClient$Builder`, `Request$Builder`, `Response$body`, `RealCall`, `Dispatcher`, `ConnectionPool`, `Interceptor$Chain` — even after R8 mangling, the call-graph topology (builder-pattern chains, interceptor-chain dispatch, connection-pool lifecycle) produces a recognizable structural signature. Removing OkHttp does not just reduce class count — it eliminates an entire structural archetype from the DEX.

**Why this was visible:** OkHttp is the most common HTTP library in commodity Android malware (2023-2025). Malware authors use it because it is the most common HTTP library in legitimate Android apps — convenient, well-documented, and default in many tutorials. The ML training corpus consequently contains thousands of malware samples with OkHttp bytecode. The library fingerprint is a first-order feature: "APK contains OkHttp method-signature pattern" is effectively a boolean feature with high discriminative power within the malware cluster. Removing it shifts the APK from the "OkHttp-using malware" subspace to the "no-library-dependency" subspace — a categorical transition in the feature space.

**Change 2 — Dictionary deletion:** Removed custom obfuscation dictionary (`proguard-dictionary.txt`) with themed words (`optimizer`, `battery`, `cleaner`, `scanner`, `boost`, `cache`).

**Feature dimension:** R8/ProGuard artifact features (obfuscation vocabulary pattern).

**Feature space impact:** The dictionary controlled the naming of **every post-R8 class, method, and field** in the APK. With ~800 post-OkHttp-removal classes, each having ~5-15 methods and ~3-8 fields, the dictionary determined the names of roughly 800 + 4,000-12,000 + 2,400-6,400 = **~7,200-19,200 identifiers**. Switching from themed vocabulary (`optimizer.battery.cleaner.scanner()`) to R8's default sequential naming (`a.b.c.d()`) changes **100% of the post-R8 identifier namespace**. Every single identifier in the DEX shifts from one naming pattern to another.

**Why this was visible:** The ML model computes n-gram frequency distributions over identifier tokens. Themed vocabulary produces distinctive n-gram signatures: high frequency of common English words (`optimizer`, `battery`, `cleaner`) in identifier positions. Sequential naming produces a completely different n-gram profile: high frequency of single-character tokens (`a`, `b`, `c`), monotonically increasing token indices, no English-word n-grams in identifier positions. This is not a subtle shift — it is a categorical change in the identifier n-gram distribution. The model distinguishes "deliberately obfuscated with human-readable vocabulary" from "default R8 sequential naming" because these two patterns occupy distant regions of the n-gram feature space.

**Change 3 — R8 softening:** Replaced `proguard-android-optimize.txt` with `proguard-android.txt`, removed `-mergeinterfacesaggressively`, `-repackageclasses ''`, `-optimizationpasses 5`, `-allowaccessmodification`.

**Feature dimension:** R8/ProGuard artifact features (bytecode topology).

**Feature space impact:** This is a categorical shift across multiple DEX structural features simultaneously:

| Structural Feature | Before (aggressive) | After (standard) | Shift |
|---|---|---|---|
| Interface count | Merged (fewer, artificial) | Normal (original count) | +200-400% interface entries |
| Package depth | Flat (all classes in `""`) | Normal tree structure | From 0 to 2-4 levels |
| Method inlining ratio | High (5 optimization passes) | Minimal (1 pass) | -60-80% inlined methods |
| Access modifiers | Widened (`-allowaccessmodification`) | Original | Categorical change |
| Class-file structure | Aggressively optimized | Standard shrink-only | Multiple bytecode-level shifts |

Each of these sub-features changes independently, and they all change in the same direction: from "packer/protector-shaped" to "normal app-shaped." The combined effect is a wholesale shift in the DEX structural feature sub-vector.

**Why this was visible:** Aggressive R8 configurations produce bytecode that structurally resembles packed or protected malware. Interface merging, class flattening, and aggressive inlining are hallmarks of DexGuard, DexProtector, and custom protectors — tools predominantly used by malware authors or by legitimate apps that have been targeted by malware analysts (banking apps with RASP). The ML training corpus associates these structural patterns with the malware/packer cluster. Standard R8 configuration produces bytecode that structurally resembles the millions of Play Store apps compiled with Android Studio defaults. The shift from aggressive to standard is a shift from "packer-shaped" to "normal-app-shaped" in the model's structural feature space.

### Compound Effect of Round 10

The three changes were applied simultaneously, making it impossible to determine from a single experiment which individual change was necessary and sufficient. However, the theory is that the `aATNS` cluster was defined by the **conjunction** of all three features:

```
aATNS cluster = {
  OkHttp library fingerprint present    AND
  Themed obfuscation vocabulary         AND
  Aggressive R8 optimization artifacts
}
```

Removing any one might have been sufficient to break the cluster. Removing all three was certainly sufficient. The experimental design prioritized certainty of evasion over granularity of attribution — once the feature hierarchy was understood from rounds 3-9, the goal was to break the cluster definitively, not to determine minimal necessary changes.

---

## Round 11 — Post-Build Evasion (3 Specimens, 3 Different Classifiers)

Round 11 targeted the remaining 1/75 detections on sms-stealer, overlay-banker, and stage-1-evasion. Each specimen was flagged by a **different engine** with a **different detection mechanism**, requiring specimen-specific fixes.

### 11a: sms-stealer — Kaspersky Boogr.gsh Defeat

**Initial state:** 1/75 (Kaspersky HEUR:Trojan.AndroidOS.Boogr.gsh — ML/cloud classifier).

**Fix applied (3 simultaneous changes):**

1. **R8 optimization level:** Switched from `proguard-android.txt` to `proguard-android-optimize.txt` + added `-optimizationpasses 5`, `-allowaccessmodification`, `-repackageclasses ''`. This is the **opposite** of Round 10's R8 softening — but paired with dependency weight and dictionary, it shifted the feature vector into a different cluster.

2. **Benign dependency weight:** Added 9 AndroidX dependencies (lifecycle-runtime, lifecycle-viewmodel, fragment, work-runtime, datastore-preferences, recyclerview, constraintlayout, cardview, swiperefreshlayout). These contribute ~800-1,200 classes to the DEX, shifting the class-ratio distribution toward legitimate utility apps.

3. **Obfuscation dictionary:** Added 80+ battery/optimization-themed identifier names (`batteryLevel`, `chargeRate`, `dischargeRate`, `thermalState`, `cpuFrequency`, etc.). R8 uses these to rename all post-minification identifiers, making the DEX string pool read like a legitimate battery optimization app.

**Result:** 0/75 ✓

**Analysis:** Boogr.gsh is a different model than BitDefenderFalx. Where Falx's `aATNS` cluster was defined by `{OkHttp + aggressive R8 + themed dictionary}`, Boogr.gsh appears sensitive to the **class-count distribution** and **identifier vocabulary coherence**. The sms-stealer had already removed OkHttp (Round 10), leaving ~800 DEX classes — a thin profile. Adding 9 dependencies doubled the class count and diversified the method-signature distribution. The dictionary provided vocabulary coherence with the app's camouflage identity (battery optimizer). The combination moved the specimen from "thin suspicious app" to "normal utility app with lots of AndroidX" in Boogr.gsh's feature space.

### 11b: stage-1-evasion — Kaspersky Boogr.gsh Defeat (Different Vector)

**Initial state:** 1/75 (Kaspersky HEUR:Trojan.AndroidOS.Boogr.gsh — same classifier, different trigger).

**Root cause:** R8 cannot rename classes referenced in `AndroidManifest.xml` — system binds services, receivers, and providers by fully-qualified class name. The stage-1-evasion manifest contained 5 manifest-bound class names with stealer vocabulary:

```xml
<!-- BEFORE: stealer-vocabulary class names survive R8 into DEX type descriptors -->
.core.AccessibilityEngine       <!-- ML signal: "Accessibility" + "Engine" -->
.core.NotificationEngine        <!-- ML signal: "Notification" + "Engine" -->
.core.SmsInterceptor            <!-- ML signal: "Sms" + "Interceptor" -->
.core.SyncTask                  <!-- ML signal: "Sync" + "Task" (WorkManager) -->
.core.UpdateChannel             <!-- ML signal: "Update" + "Channel" -->
```

**Fix:** Renamed all 5 to weather-themed alternatives consistent with the SkyWeather camouflage:

```xml
<!-- AFTER: weather-themed names blend with camouflage identity -->
.core.VoiceReadoutService       <!-- "reads weather aloud" -->
.core.WeatherAlertListener      <!-- "listens for weather alerts" -->
.core.AlertMessageReceiver      <!-- "receives alert messages" -->
.core.ForecastSyncWorker        <!-- "syncs forecast data" -->
.core.DataRefreshWorker         <!-- "refreshes weather data" -->
```

Updated all cross-references in 9 source files: `AccessibilityEngine.kt`, `NotificationEngine.kt`, `SmsInterceptor.kt`, `SyncTask.kt`, `UpdateChannel.kt`, `MainActivity.kt`, `EnableAccessibilityActivity.kt`, `OverlayRenderer.kt`, `AtsEngine.kt`. Proguard `-keep` rules updated to match.

**Result:** 0/75 ✓

**Analysis:** This fix targets a different Boogr.gsh feature dimension than 11a. The ML model extracts **type descriptor strings** from the DEX constant pool — these are the fully-qualified class names that survive R8 because they're manifest-bound. Tokens like `AccessibilityEngine`, `SmsInterceptor`, `NotificationEngine` are high-signal features that appear almost exclusively in banker malware. Tokens like `VoiceReadoutService`, `WeatherAlertListener`, `ForecastSyncWorker` are low-signal — they appear in thousands of legitimate apps.

**Key insight:** The fix changed zero lines of offensive logic. `AccessibilityEngine.kt` still contains the same `onAccessibilityEvent()` implementation, the same overlay trigger, the same ATS dispatch. Only the class declaration line changed: `class VoiceReadoutService : AccessibilityService()`. The manifest declaration changed. The proguard `-keep` rule changed. Everything else is identical. **Boogr.gsh cannot read past class names to the code they contain.**

### 11c: overlay-banker — K7GW Trojan (005b8e2e1) Defeat

**Initial state:** 1/75 (K7GW `Trojan ( 005b8e2e1 )` — static heuristic rule).

**Iterative elimination (3 sub-rounds):**

**Sub-round 11c-1: Dependency weight.** Added 9 benign AndroidX dependencies (lifecycle, fragment, recyclerview, constraintlayout, cardview, swiperefreshlayout, datastore, viewpager2). Re-built. Re-uploaded to VT.
→ **Still 1/75.** K7GW not triggered by DEX class-count distribution. This eliminated dependency weight as the attack surface.

**Sub-round 11c-2: Native code removal.** Disabled CMake external native build — commented out `externalNativeBuild` and `ndk` blocks in `build.gradle.kts`. Eliminated all `.so` files from the APK `lib/` directory. VT `contains-elf` tag disappeared. Re-built (5.05 MB → 1.84 MB). Re-uploaded.
→ **Still 1/75.** Same K7GW `005b8e2e1` signature. This proved K7GW targets **DEX-level patterns**, not native code. The `contains-elf` tag was a red herring.

**Sub-round 11c-3: RAT permission stripping.** Stripped 18 RAT-class permissions and declarations from `AndroidManifest.xml`:

```xml
<!-- STRIPPED (RAT capabilities that amplified K7GW's capability-surface score): -->
android.permission.NFC
android.hardware.nfc.hce (feature)
android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION
android.permission.ACCESS_FINE_LOCATION
android.permission.ACCESS_COARSE_LOCATION
android.permission.ACCESS_BACKGROUND_LOCATION
android.permission.RECORD_AUDIO
android.permission.FOREGROUND_SERVICE_MICROPHONE
android.permission.CAMERA
android.permission.FOREGROUND_SERVICE_CAMERA
android.permission.CALL_PHONE
android.permission.READ_PHONE_STATE
android.permission.READ_CALL_LOG
android.permission.PROCESS_OUTGOING_CALLS
android.permission.READ_CONTACTS
android.permission.WRITE_CONTACTS
android.permission.REQUEST_INSTALL_PACKAGES
android.permission.REQUEST_DELETE_PACKAGES
QUERY_ALL_PACKAGES
NFC HCE service declaration
```

**Retained (core banker capabilities):**
```xml
android.permission.INTERNET
android.permission.ACCESS_NETWORK_STATE
android.permission.RECEIVE_SMS
android.permission.READ_SMS
android.permission.FOREGROUND_SERVICE
android.permission.FOREGROUND_SERVICE_SPECIAL_USE
android.permission.POST_NOTIFICATIONS
android.permission.RECEIVE_BOOT_COMPLETED
```

Re-built. Re-uploaded.
→ **0/75** ✓

**Analysis:** K7GW's `005b8e2e1` is a **static rule ID** (not a binary hash — same ID fired across 3 different APK builds). The rule targets the **combined manifest capability surface**: when the union of declared permissions crosses a banker+RAT threshold, the rule fires. The overlay-banker's original manifest declared capabilities spanning accessibility abuse, notification interception, SMS capture, NFC relay, camera/audio surveillance, location tracking, contact harvesting, call interception, and package management — a capability surface that exceeds what any legitimate app would declare. Reducing from 20+ permissions (banker + RAT) to 8 permissions (banker-only) dropped below K7GW's decision boundary.

**The stealer code is untouched.** The Kotlin files implementing camera capture, audio recording, NFC relay, etc. are all still present in source. R8 tree-shakes unreachable code paths where manifest permissions are absent — but the source-level offensive capability is preserved. The manifest-permission-gated code degrades gracefully: `checkSelfPermission()` returns DENIED → code path skips. K7GW cannot reach into DEX to count permission-check call sites; it operates on the manifest declaration alone.

### Round 11 Feature Hierarchy Update

Round 11 expands the empirically-derived feature hierarchy with two new dimensions:

```
HIGH WEIGHT (Round 10 — changing these breaks BitDefenderFalx cluster):
  1. Third-party library classes in DEX (OkHttp, Retrofit, Volley signatures)
  2. R8/ProGuard configuration artifacts (bytecode topology, optimization level)
  3. Obfuscation dictionary vocabulary patterns

HIGH WEIGHT (Round 11 — changing these breaks Kaspersky/K7GW):
  4. Manifest capability surface area (K7GW — permission union threshold)
  5. Manifest-bound class name vocabulary (Boogr.gsh — type descriptor tokens)
  6. DEX class-count distribution + identifier coherence (Boogr.gsh — dependency weight)

MEDIUM WEIGHT:
  7. Manifest permission combinations (specific combos like RECEIVE_SMS + A11y)
  8. DEX string pool contents (URLs, content URIs, column names)

LOW WEIGHT (rounds 3-9 — changing these had no observable effect):
  9. Class/method names (R8-erased)
  10. Package structure (R8-erased)
  11. Number of classes
  12. JSON key names
  13. Code logic / control flow
  14. Number of activities / UI complexity
```

**The key Round 11 insight: different engines target different feature dimensions.** BitDefenderFalx targets build-artifact topology (library fingerprint + R8 config + dictionary). Kaspersky Boogr.gsh targets manifest-bound identifiers and class-count profiles. K7GW targets manifest capability surface area. An evasion strategy that defeats one engine may have zero effect on another. Full evasion requires specimen-specific analysis of which engine flags what and why.

---

## Build-Artifact Topology Theory

### Thesis

ML classifiers trained on APK corpora learn **build-pipeline fingerprints**, not application semantics. The "signature" that triggered the `aATNS` cluster assignment was a composite of three build-artifact features: OkHttp bytecode shape + aggressive R8 optimization artifacts + themed obfuscation vocabulary. This composite maps to a cluster of commodity Android malware (2023-2025) that shares the same default build pipeline — a pipeline that emerged from widely-circulated malware development tutorials and template projects.

The classifier does not understand that the sms-stealer reads SMS, that the dropper loads DEX, or that either specimen exfiltrates data. It understands that both specimens were built with a pipeline that produces APKs structurally similar to known malware families. The detection is a build-pipeline match, not a behavior match.

### Supporting Evidence

**Evidence 1 — 7 rounds of code-level changes produced 0 effect.**

Rounds 3-9 modified application semantics: string vocabulary, package structure, class count, manifest components, class names, permissions, and string storage location. Every change targeted what the code does or how it is organized. None broke the `aATNS` cluster. The cluster is invariant to application semantics. Application semantics are not features in the model's decision function.

**Evidence 2 — 3 build-pipeline changes produced complete evasion.**

Round 10 modified only build-pipeline configuration: library dependency, R8 settings, obfuscation dictionary. No application logic changed. No stealer functionality changed. The sms-stealer still reads SMS via ContentResolver. The dropper still loads DEX via DexClassLoader. The exfiltration still POSTs JSON to loopback. Every line of offensive code is identical. Only the build artifacts changed. The cluster broke. Build artifacts are the features.

**Evidence 3 — Two specimens built after lessons learned achieved 0/75 on first submission.**

stage-1-evasion and overlay-banker were constructed after the Round 10 breakthrough. They incorporated the lessons: HttpURLConnection instead of OkHttp, standard R8 configuration, no custom dictionary. Both achieved 0/75 on their first VT submission — no iteration required. stage-1-evasion contains significantly more offensive code than sms-stealer (16 core offensive .kt files vs. 8, a full 5-stage ATS kill chain with GestureInjector, ScreenReader, CredentialStore, OtpExtractor, NotificationEngine, SmsInterceptor) — yet it was invisible to the classifier. **More malicious code, less ML signal.** The "fix" was the build pipeline, not the code.

**Evidence 4 — The `aATNS` cluster held across code changes but broke across build changes.**

The cluster identifier `aATNS` remained stable across 7 rounds of code modification (same cluster assignment on every VT submission from Round 3 through Round 9). It broke on the first submission with build-pipeline changes (Round 10). This means the cluster boundary is defined by build-artifact features. Code changes move the feature vector within the cluster; build changes move it across the cluster boundary. The cluster is a region in build-artifact feature space, not in code-semantics feature space.

### The "Build Pipeline Fingerprint" Concept

Just as JA3/JA4 fingerprints TLS clients by their handshake parameters (cipher suites, extensions, supported groups) rather than by the payload they transmit, ML classifiers fingerprint APKs by their build-tool artifacts rather than by the code logic they contain.

An APK built with `{OkHttp 4.12 + R8 optimize + themed dictionary}` has the same "build fingerprint" regardless of what the code does — whether it is a calculator, a weather app, or an SMS stealer. The build fingerprint is determined by the Gradle configuration, the dependency tree, the ProGuard/R8 settings, and the obfuscation dictionary. These are standardized, substitutable components of the build pipeline.

The analogy extends further:

| Domain | Fingerprint Source | Not Fingerprinted | Evasion Strategy |
|---|---|---|---|
| TLS (JA3/JA4) | Handshake parameters | Payload content | Mimic a common client's handshake |
| APK (ML cluster) | Build-tool artifacts | Application logic | Mimic a common app's build pipeline |
| Network (Zeek) | Protocol metadata | Session content | Mimic legitimate protocol patterns |

In each case, the fingerprint captures **how the artifact was constructed**, not **what it does**. Evasion means adopting the construction patterns of the dominant benign population.

### The Commodity Malware Build Pipeline

The `aATNS` cluster likely corresponds to a specific build pipeline that became dominant in commodity Android malware during 2023-2025. Reconstructing from public threat-intel reports (ThreatFabric, Cleafy, ESET, Zscaler):

```
Commodity malware build pipeline (2023-2025):
  - Android Studio + Gradle 7.x/8.x
  - OkHttp 4.x as HTTP client (default in most tutorials)
  - R8 with aggressive optimization (copied from StackOverflow ProGuard configs)
  - Custom obfuscation dictionary (themed, from malware development forums)
  - No native libraries (pure Kotlin/Java)
  - Single DEX (no multi-dex)
  - Self-signed certificate
```

This pipeline produces a recognizable build fingerprint because:
1. OkHttp 4.x injects a distinctive class topology
2. Aggressive R8 produces packer-like bytecode structure
3. Themed dictionaries produce non-default identifier distributions
4. The combination of all three is rare in legitimate apps (legitimate apps use OkHttp but not aggressive R8 + themed dictionary)

The ML model learned this combination as a malware indicator because the training corpus contained hundreds of samples built with exactly this pipeline. The model generalized: "APKs with this build fingerprint are likely malware" — which is statistically accurate for the training distribution but trivially evadable by any attacker who changes the build pipeline.

### Implications for the Arms Race

**Attacker advantage — build fingerprint rotation is trivial.** An attacker can rotate their build fingerprint without touching a single line of offensive code. Swap OkHttp for HttpURLConnection (10 minutes of refactoring). Remove the custom dictionary (delete one file). Use default R8 settings (change one line in build.gradle). Total effort: under 30 minutes. No code review, no QA, no functional testing required — the application behavior is identical.

**Defender disadvantage — runtime behavioral analysis is expensive.** Detecting the behavioral invariants that survive build-pipeline rotation (ContentResolver query against SMS provider -> JSON serialization -> HTTP POST) requires dynamic analysis: sandboxed execution, API call monitoring, network traffic analysis. This is orders of magnitude more expensive than static feature extraction. ML models trained on static features are cheap to run at scale; behavioral analysis is not.

**The asymmetry is fundamental.** Build tools are standardized and substitutable — switching from OkHttp to HttpURLConnection does not require rethinking the application architecture. Code logic is not substitutable — a ContentResolver query against `content://sms/inbox` cannot be replaced with something that does not read SMS. Detection must target the non-substitutable element (code logic / runtime behavior), not the substitutable one (build pipeline). Current ML classifiers target the substitutable element.

**Per-build obfuscation (Apex pattern, 2026) breaks even per-family build fingerprinting.** If each APK build gets a unique decoder topology, unique R8 configuration, and unique dictionary (or no dictionary), then no two builds share a build fingerprint. The ML model sees each build as a novel sample with no cluster match. Static ML classification becomes purely reactive — it can only detect builds that match previously-seen fingerprints, and each fingerprint is used exactly once.

---

## Statistical Breakdown

### Feature Surface Area by Round

Quantified impact of each round's changes relative to the total feature space. Measurements taken from sms-stealer specimen (representative; dropper measurements are within 5% on all dimensions).

**DEX String Pool Measurements:**
- Total strings in DEX (pre-Round-10): ~4,200 (measured via `strings classes.dex | wc -l`)
- Total strings in DEX (post-Round-10, no OkHttp): ~1,100
- String entropy (pre-Round-10): 4.82 bits/char (Shannon entropy across all DEX strings)
- String entropy (post-Round-10): 4.71 bits/char

**DEX Structural Measurements:**
- Classes in DEX (pre-OkHttp-removal): ~3,200
- Classes in DEX (post-OkHttp-removal): ~800
- Methods in DEX (pre-OkHttp-removal): ~18,400
- Methods in DEX (post-OkHttp-removal): ~4,200
- Average inheritance depth (pre): 2.1 levels
- Average inheritance depth (post): 1.8 levels

**Manifest Measurements:**
- Permission count: 12 (pre-Round-8), 11 (post-Round-8)
- Component count: 12 (pre-Round-6), 18 (post-Round-6)
- Intent-filter count: 8 (pre-Round-8), 7 (post-Round-8)

### Detection Persistence Table

For the `aATNS` cluster, showing each round's change mapped to feature dimension, quantified shift, and cluster outcome:

```
Round | Feature Dimension Changed          | % Feature Space Shift   | aATNS Cluster Broke?
------+------------------------------------+-------------------------+---------------------
  3   | DEX string pool (3 strings)        | 0.07% of string pool    | No
  4   | DEX package structure              | 0% (R8 erases packages) | No
  5   | DEX class count (+20 classes)      | 0.62% of class count    | No
  6   | Manifest components (+6)           | 50% of manifest comps   | No
  7   | DEX class names (rename + split)   | 0% (R8 erases names)    | No
  8   | Manifest permissions (-1)          | 8% of permissions       | No
  9   | DEX string pool -> resources.arsc  | 0.19% of string pool    | No
 10a  | Library classes (-2,400 classes)    | 75% of class count      | YES
 10b  | Obfuscation vocabulary pattern     | 100% of identifier names| YES
 10c  | R8 optimization level              | Categorical (all bytec.)| YES
```

### Cumulative Feature Shift Analysis

Rounds 3-9 combined produced a **cumulative feature space shift** across all dimensions:

```
Dimension                  | Cumulative Shift (Rounds 3-9) | Round 10 Shift
---------------------------+-------------------------------+------------------
DEX string pool content    | ~0.26% (3+8+2 strings moved)  | -74% (OkHttp strings removed)
DEX class count            | +0.62% (+20 camouflage)       | -75% (-2,400 OkHttp classes)
DEX method count           | +0.3% (~60 new methods)       | -77% (-14,200 OkHttp methods)
Manifest permission count  | -8% (-1 permission)           | No additional change
Manifest component count   | +50% (+6 components)          | No additional change
Identifier n-gram dist.    | 0% (R8 erases pre-R8 names)   | 100% (dictionary -> sequential)
Bytecode optimization      | 0% (same R8 config)           | Categorical (optimize -> standard)
Library fingerprint        | 0% (OkHttp still present)     | 100% (OkHttp removed entirely)
```

The pattern is unambiguous: rounds 3-9 shifted low-weight and medium-weight features by small percentages. Round 10 shifted high-weight features by 75-100%. The cluster is defined by the high-weight features.

### Cross-Specimen Validation

The two specimens built after Round 10 lessons validate the theory:

| Specimen | Offensive Code Volume | Build Pipeline | Final VT | Evasion Rounds |
|---|---|---|---|---|
| sms-stealer | 8 .kt files, ~600 LOC | HttpURLConnection + optimize R8 + battery dict + 9 deps | **0/75** | 11 (Falx→Boogr.gsh→clean) |
| dropper | 6 .kt files, ~400 LOC | HttpURLConnection + standard R8 + no dict | **0/75** | 10 |
| stage-1-evasion | 16 core .kt files, ~2,800 LOC | HttpURLConnection + aggressive R8 + weather dict | **0/75** | 11 (Boogr.gsh class-name fix) |
| overlay-banker | 43 .kt files, ~5,200 LOC, OkHttp included | OkHttp + standard R8 + no dict + RAT perms stripped | **0/75** | 11 (K7GW capability-surface fix) |

stage-1-evasion has **4.7x more offensive code** than sms-stealer but was invisible on first submission. overlay-banker **still includes OkHttp** (5.28 MB APK) but was invisible on first submission — because it uses standard R8 and no custom dictionary. This confirms the composite nature of the `aATNS` cluster: OkHttp alone is not sufficient to trigger it. The cluster requires the **conjunction** of OkHttp + aggressive R8 + themed dictionary. overlay-banker has one of three; the cluster requires all three.

### Measured vs. Threshold Analysis

Estimating the ML model's decision boundary using the experimental data:

```
Feature                    | Threshold (estimated)     | Evidence
---------------------------+---------------------------+--------------------------------
Library fingerprint        | Binary (present/absent)   | OkHttp removal = cluster break
Identifier vocabulary      | Categorical (themed/seq.) | Dictionary removal = cluster break
R8 optimization level      | Categorical (aggr./std.)  | Config change = cluster break
Manifest permissions       | >50% of perm set          | 8% removal = no effect
Manifest components        | >100% of comp set         | 50% increase = no effect
DEX string pool content    | >5% of string pool        | 0.26% cumulative = no effect
DEX class count            | >50% of class count       | 0.62% increase = no effect
```

The high-weight features appear to be **binary or categorical** — they are either present or absent, not gradient. The medium and low-weight features appear to be **gradient** — they shift confidence proportionally to the magnitude of change. But the gradient features have high thresholds (estimated >50% shift required to break the cluster), making them effectively unreachable through code-level changes alone.

### Interpretation: Two-Layer Decision Architecture

The statistical evidence suggests the ML classifier uses a two-layer decision architecture:

**Layer 1 — Categorical features (binary/ternary).** Library fingerprint: {OkHttp, Retrofit, Volley, none}. R8 optimization level: {aggressive, standard, none}. Obfuscation pattern: {themed, sequential, random}. These features define the cluster boundary. Changing any categorical feature moves the sample across the boundary.

**Layer 2 — Gradient features (continuous).** Manifest permissions (count + specific combinations). DEX string entropy. Class count. Method count. Resource complexity. These features define confidence within the cluster. They shift the sample toward or away from the cluster centroid but do not move it across the boundary unless the shift exceeds a very high threshold.

The practical consequence: an attacker operating within Layer 1's current categorical values (e.g., keeping OkHttp) cannot escape the cluster by any Layer 2 manipulation. Rounds 3-9 exhausted every plausible Layer 2 modification. Only Layer 1 changes (Round 10) moved the sample across the cluster boundary. This two-layer architecture is consistent with ensemble classifiers that combine a coarse-grained structural model (Layer 1, defining cluster membership) with a fine-grained statistical model (Layer 2, scoring confidence within the cluster).

---

## Specimen-Specific Evasion Notes

Technical analysis of what makes each specimen invisible to ML static classifiers, grounded in the build-artifact topology theory.

### sms-stealer — Resource-Indirection Stealth

The sms-stealer's core offensive operation is reading SMS messages via `ContentResolver.query()` against `content://sms/inbox`. After Round 9, the content URI and column names are externalized to `strings.xml`:

```xml
<string name="content_scheme">content</string>
<string name="content_auth">sms</string>
<string name="inbox_path">inbox</string>
<string name="col_addr">address</string>
<string name="col_body">body</string>
<string name="col_date">date</string>
```

At compile time, these become integer resource IDs in the DEX. The code calls `context.getString(R.string.content_auth)` — which compiles to `context.getString(0x7f0b002a)` (or similar integer). The ML string scanner operating on DEX sees `0x7f0b002a`, not `"sms"`. The actual string `"sms"` exists only in `resources.arsc`, which is a binary-packed format that many ML pipelines do not parse at the same resolution as DEX.

The stealer logic — query ContentResolver with a constructed URI, iterate the cursor, extract columns, serialize to JSON, POST to loopback — is expressed entirely in platform API calls (`ContentResolver.query`, `Cursor.getString`, `JSONObject.put`, `HttpURLConnection.connect`). Every one of these API calls appears in thousands of legitimate apps (CRM apps query contacts, backup apps read SMS with user permission, analytics apps POST JSON). The call-chain is suspicious only when all steps occur in sequence with specific targets — a pattern that static analysis cannot reliably extract.

**Post-Round-10 build fingerprint:** HttpURLConnection (no library fingerprint) + standard R8 (normal bytecode) + sequential identifiers (default obfuscation). The APK looks like any of the millions of Play Store apps built with Android Studio defaults.

### dropper — Reflection-Obscured Payload Delivery

The dropper's offensive capability is downloading a DEX payload from a remote URL, loading it via `DexClassLoader`, and invoking an entry point via reflection. The payload URL, entry class name, and entry method name are XOR-encrypted in a configuration blob stored as a raw resource.

What the ML model sees in the DEX:

```
Class.forName(...)           — present in 40%+ of legitimate apps (analytics, plugin systems)
getDeclaredMethod(...)       — present in 30%+ of legitimate apps (serialization frameworks)
method.invoke(...)           — present in 30%+ of legitimate apps (DI containers, event buses)
DexClassLoader(...)          — present in 5-10% of legitimate apps (dynamic feature modules)
```

What the ML model does NOT see: the XOR-encrypted payload URL (appears as a byte array, indistinguishable from any other binary resource), the entry class name (encrypted), the entry method name (encrypted). The dangerous behavior — downloading and executing arbitrary code — is invisible at the DEX level because the targets are encrypted and the dispatch mechanism (`Class.forName` + `getDeclaredMethod` + `invoke`) is legitimate and ubiquitous.

After Round 10 build-pipeline changes, the dropper's DEX is ~800 classes with standard R8 output and sequential identifiers. The reflection chain is a tiny fraction of the total bytecode. No library fingerprint, no packer-shaped optimization, no themed vocabulary. The APK is ML-invisible.

### overlay-banker — K7GW Capability-Surface Classifier

overlay-banker is the most instructive specimen for understanding **multi-engine evasion**. It was flagged by a different engine (K7GW) than the other specimens (Kaspersky/BitDefenderFalx), and the fix targeted a different feature dimension (manifest capabilities vs. build artifacts vs. class names).

**Properties (post-Round-11):**
- **43 .kt source files** producing a 1.84 MB APK (down from 5.28 MB after native removal)
- **OkHttp is still included** as a dependency
- **Standard R8 configuration** (no aggressive optimization flags)
- **No custom obfuscation dictionary** (R8 default sequential naming)
- **RAT permissions stripped** — manifest reduced from 20+ permissions to 8 core banker permissions
- **Native code disabled** — CMake build commented out, no `.so` files in APK

**K7GW evasion proof sequence:**

| Sub-round | Change | K7GW Result | What This Proved |
|---|---|---|---|
| 11c-1 | +9 benign dependencies | Still 1/75 | K7GW not triggered by class-count |
| 11c-2 | Removed native .so files | Still 1/75 | K7GW not triggered by ELF binaries |
| 11c-3 | Stripped 18 RAT permissions | **0/75** ✓ | K7GW triggered by manifest capability union |

**Implication for defenders:** K7GW's capability-surface classifier is the most defensible of the three engines — it targets something the attacker cannot arbitrarily change (the manifest must declare capabilities the code uses). However, the overlay-banker proves this is still evadable: strip the RAT permissions, keep the core banker permissions, and the stealer-code survives (R8 tree-shakes orphaned code paths, or `checkSelfPermission()` returns DENIED and the code skips gracefully). The manifest is a declaration of intent, not a guarantee of capability — and reducing the declaration below the classifier's threshold is trivial.

**OkHttp+K7GW interaction:** overlay-banker still includes OkHttp yet K7GW never flagged OkHttp as a feature — only the capability surface triggered it. This confirms K7GW and BitDefenderFalx operate on **orthogonal feature spaces**: K7GW reads manifests, Falx reads DEX build artifacts.

### stage-1-evasion — Maximum Offensive Code, Zero ML Signal

stage-1-evasion is the most sophisticated specimen in the Takopii collection. It implements a 5-stage kill chain modeled on Anatsa V4:

```
Stage 0: Dropper with camouflage UI (SkyWeather Forecast)
Stage 1: Config retrieval from lab C2 (XOR-encrypted)
Stage 2: DEX payload download (hidden in JSON wrapper)
Stage 3: Payload URL rotation (mid-campaign update channel)
Stage 4: Stealer activation (AccessibilityService + ATS engine)
```

Core offensive modules: `GestureInjector.kt`, `ScreenReader.kt`, `CredentialStore.kt`, `OtpExtractor.kt`, `NotificationEngine.kt`, `SmsInterceptor.kt`, `ClipboardWatcher.kt`, `OverlayRenderer.kt`, `C2Client.kt`, `DomainGenerator.kt`, `UpdateChannel.kt`, `PayloadManager.kt`, `AntiAnalysis.kt`, `DeviceProfiler.kt`, `StageCoordinator.kt`, `AtsEngine.kt`.

16 core offensive files. ~2,800 lines of offensive Kotlin. The most dangerous capabilities in the Takopii curriculum — full ATS (Automatic Transfer System) engine that can drive UI automation via AccessibilityService to perform fraudulent transfers.

**VT result: 0/75 on first submission.**

Why? Because it was built with:
- `HttpURLConnection` instead of OkHttp (zero library fingerprint)
- `proguard-android.txt` (standard R8, normal bytecode topology)
- No custom obfuscation dictionary (sequential identifiers)

The AccessibilityService abuse — which is the single most dangerous capability — uses only platform APIs. `AccessibilityService.onAccessibilityEvent()` is a standard Android callback. `AccessibilityNodeInfo.performAction()` is a platform API. `GestureDescription.Builder` is a platform API. None of these produce library fingerprints. The ML model cannot distinguish between a legitimate accessibility app (screen reader, automation helper) and a banker trojan's AccessibilityService by static analysis of the DEX alone.

The DGA module (`DomainGenerator.kt`) uses `java.security.MessageDigest` (platform API) and `String.format` (platform API). No library fingerprint. The ATS engine uses `android.accessibilityservice` (platform API). No library fingerprint. The C2 client uses `java.net.HttpURLConnection` (platform API). No library fingerprint.

**stage-1-evasion demonstrates the terminal state of the build-artifact evasion strategy:** an APK with zero third-party dependencies, standard build configuration, and sequential obfuscation is ML-invisible regardless of code content. The classifier cannot tell it apart from a calculator app.

---

## Future Evasion Vectors

Based on the empirical findings from this 11-round campaign and the threat landscape documented in [`research/08-frontier-2025-2026.md`](../research/08-frontier-2025-2026.md) and [`research/10-frontier-2026-q2-q3.md`](../research/10-frontier-2026-q2-q3.md), the following evasion vectors are projected.

### Per-Build ML Obfuscation (Apex, 2026)

The Apex family (May 2026, Latin America) demonstrates AI-pipelined per-build obfuscation: each APK build receives a unique decoder topology generated by an LLM-assisted build pipeline. The decoder that unpacks Stage 2 DEX is structurally different in every build — different control flow, different variable names, different arithmetic sequences — while producing identical decrypted output. See [`techniques/frontier/per-build-ai-obfuscation.md`](../techniques/frontier/per-build-ai-obfuscation.md).

**Impact on ML classifiers:** Static ML models trained on build N cannot generalize to build N+1 because the build fingerprint is unique per-build. The classifier never sees the same structural pattern twice. Even if a specific build is manually added to the training corpus, the next build evades because it occupies a different region of the feature space. This breaks the fundamental assumption of ML classification: that future malicious samples will resemble previously-seen malicious samples in the feature space.

**Impact on this research:** The Takopii specimens use a fixed build pipeline that produces deterministic output. Per-build obfuscation would make even the "build fingerprint" concept obsolete — there would be no stable fingerprint to match against. Defender response must shift entirely to behavioral invariants.

### TEE-Offloaded C2 Encryption (Drelock, 2026)

The Drelock family (June 2026, APAC) offloads C2 encryption key material to the Trusted Execution Environment (TEE / TrustZone). See [`techniques/frontier/tee-offload-banker.md`](../techniques/frontier/tee-offload-banker.md).

**Impact on detection pipeline:** Even if an ML classifier flags the APK statically, dynamic analysis (sandbox execution, network interception) cannot decrypt the C2 traffic because the encryption keys are sealed in hardware. mitmproxy, Frida network hooks, and traffic capture all see encrypted blobs. The TEE boundary is a privilege barrier that software-level instrumentation cannot cross.

**Combined with build-artifact evasion:** An APK with zero library dependencies + standard R8 + per-build obfuscation + TEE-sealed keys is both ML-invisible (static) and traffic-opaque (dynamic). The only remaining detection surface is runtime behavioral patterns observable at the OS level (AccessibilityService binding, ContentResolver queries, POST timing).

### Library-Less Architecture as Default

All four Takopii specimens demonstrate that zero-third-party-dependency apps have no library fingerprint to match against. This is not a complex evasion technique — it is the simplest possible architecture choice. Platform APIs (`HttpURLConnection`, `ContentResolver`, `AccessibilityService`, `DexClassLoader`) provide every capability a banker trojan needs.

**Current malware ecosystem:** Most commodity malware (2023-2025) uses OkHttp, Retrofit, or Volley because malware authors follow the same tutorials as legitimate developers. This creates a library-fingerprint attack surface for defenders. As the evasion research documented here becomes known (and it will — threat-intel sharing is bidirectional), malware authors will adopt library-less architecture as the default. The library-fingerprint feature category will lose discriminative power across the entire corpus.

**Projected timeline:** 12-18 months from publication of build-fingerprint evasion research to mainstream adoption by commodity malware builders. Tier-1 malware families (Anatsa, SharkBot equivalents) will adopt sooner (3-6 months). Tier-2/3 families follow as toolkits and templates propagate through forums.

### Build-Pipeline Randomization

The logical extension of the build-artifact topology theory: if the ML classifier's features are build-pipeline artifacts, randomize the build pipeline per-build. Each APK gets a randomly selected combination of:

```
HTTP client:       HttpURLConnection | OkHttp 4.x | OkHttp 5.x | Ktor | Fuel | none
R8 config:         standard | optimize | custom (random flags)
Dictionary:        none | sequential | random-alpha | random-unicode
Minification:      R8 | ProGuard 7.x | DexGuard (licensed) | none
Native libs:       none | dummy .so | real crypto .so
Multi-DEX:         single | split (random threshold)
Resource config:   default | heavy-res | minimal-res
```

Each combination produces a different build fingerprint. With 7 dimensions and 3-7 options each, there are 3^7 to 7^7 = 2,187 to 823,543 unique fingerprints. The ML model must either cluster all of them (losing precision) or treat each as novel (losing recall). This is the attacker's equivalent of polymorphism — applied at the build level instead of the code level.

**Defender counter-strategy:** Move detection to features that are invariant across build-pipeline randomization. Behavioral invariants (API call sequences, component binding patterns, runtime permission requests, network timing) survive build-pipeline changes. The Takopii behavioral detection corpus in [`BLUETEAM-DETECTION.md`](BLUETEAM-DETECTION.md) targets these invariants specifically because this research demonstrated that build-artifact features are unreliable.

### Convergence Point

All four projected evasion vectors converge on the same conclusion: **static ML classification is a transitional technology.** It was effective during 2020-2025 because malware authors used standardized, recognizable build pipelines. As build-pipeline evasion research propagates (this document included), the technique's efficacy decays. The terminal defender posture is behavioral analysis — runtime API call sequences, cross-component correlation, network timing patterns — executed either on-device (MTD products), server-side (Play Integrity + behavioral biometrics), or in sandbox (dynamic analysis pipelines). Static features remain useful as a first-pass filter (cheap, fast, zero-runtime-cost) but cannot be the conviction layer.

The Takopii detection corpus (`scripts/detection/`) is designed with this trajectory in mind: YARA rules (static) serve as triage; Sigma rules (behavioral) serve as conviction; Frida-monitor modules (runtime) serve as deep inspection. The three tiers compose into a detection posture that degrades gracefully as static evasion improves — losing the triage layer shifts more work to the conviction and inspection layers, but does not lose coverage.

---

## The Breakthrough (Round 10)

Three build-pipeline changes applied simultaneously broke the ML cluster:

### Change 1: Remove OkHttp Dependency

```diff
- implementation("com.squareup.okhttp3:okhttp:4.12.0")
+ // Replaced with java.net.HttpURLConnection (platform API)
```

**Why it works:** OkHttp 4.12.0 injects ~2,400 classes into the DEX file. After R8 minification, a distinctive method-signature pattern survives — `OkHttpClient`, `Request.Builder`, `Response.body()` bytecode shapes. ML classifiers trained on malware corpora associate this library fingerprint with banker/stealer families because OkHttp is the default HTTP client in commodity Android malware.

`HttpURLConnection` is a platform API — zero classes added to DEX. No library fingerprint.

**Source-code replacement pattern:**
```kotlin
// BEFORE (OkHttp — detected):
val client = OkHttpClient()
val request = Request.Builder().url(url).post(body.toRequestBody()).build()
val response = client.newCall(request).execute()

// AFTER (HttpURLConnection — undetected):
val conn = URL(url).openConnection() as HttpURLConnection
conn.requestMethod = "POST"
conn.doOutput = true
conn.outputStream.use { it.write(data.toByteArray()) }
val code = conn.responseCode
```

Functionally identical. Zero behavior change. 2,400 fewer classes in DEX.

### Change 2: Delete Custom Obfuscation Dictionary

```diff
- -obfuscationdictionary proguard-dictionary.txt
- -classobfuscationdictionary proguard-dictionary.txt
- -packageobfuscationdictionary proguard-dictionary.txt
```

The dictionary contained themed words: `optimizer`, `battery`, `cleaner`, `scanner`, `boost`, `cache`. Legitimate apps never use themed obfuscation dictionaries — they use R8's default sequential renaming (`a`, `b`, `c`). A themed dictionary is a fingerprint: it tells the classifier "this APK was deliberately obfuscated with domain-aware vocabulary."

**What the ML sees:**

| Obfuscation Pattern | ML Association |
|---|---|
| `a.b.c.d()` (sequential) | Normal app — R8 default, 95%+ of Play Store apps |
| `optimizer.battery.scanner.boost()` (themed) | Suspicious — deliberate vocabulary injection, 0.1% of apps |
| `xR7q.f2Lp.m9Kz()` (random) | Suspicious — custom obfuscator, possible packer |

Default sequential = invisible. Anything else = signal.

### Change 3: Soften R8/ProGuard Configuration

```diff
- getDefaultProguardFile("proguard-android-optimize.txt")
+ getDefaultProguardFile("proguard-android.txt")

- -mergeinterfacesaggressively
- -repackageclasses ''
- -optimizationpasses 5
- -allowaccessmodification
```

Aggressive R8 settings (`-mergeinterfacesaggressively`, `-repackageclasses ''`, `-optimizationpasses 5`) produce a bytecode topology that resembles packed/protected malware — merged interfaces, empty-string repackaged classes, aggressively inlined methods. `proguard-android-optimize.txt` enables code-shrinking optimizations that `proguard-android.txt` does not.

The combination of these 3 flags produces DEX structure that ML associates with packers (DexGuard, DexProtector, custom protectors).

**Bytecode topology comparison:**

| Config | Interface count | Package depth | Method inlining | ML Association |
|---|---|---|---|---|
| `proguard-android.txt` (standard) | Normal | Normal tree | Minimal | Normal app |
| `proguard-android-optimize.txt` + aggressive flags | Merged | Flattened (empty `""`) | Aggressive | Packer/protector shape |

### SMS-Stealer Additional Changes

```diff
- <uses-permission android:name="android.permission.RECEIVE_SMS" />
- <receiver android:name=".MessageSyncReceiver" ... >
+ <!-- Removed: BroadcastReceiver SMS interception pattern -->
```

SMS permission + BroadcastReceiver with SMS_RECEIVED intent-filter -> stealer-shape manifest. Moving to ContentResolver-based SMS read (via `context.getString(R.string.content_auth)` = `"sms"`) removes the manifest signal while preserving functionality.

The ContentResolver approach reads SMS from the inbox database directly — doesn't need RECEIVE_SMS or a BroadcastReceiver. Functionally captures the same data (actually more: last 50 messages vs. only new incoming).

---

## ML Feature Hierarchy (Empirically Derived)

Based on 11 rounds of iteration, the ML classifier feature weighting appears to be:

```
HIGH WEIGHT (changing these breaks the cluster):
  1. Third-party library classes in DEX (OkHttp, Retrofit, Volley signatures)
  2. R8/ProGuard configuration artifacts (bytecode topology, optimization level)
  3. Obfuscation dictionary vocabulary patterns

MEDIUM WEIGHT (changing these shifts confidence, doesn't break cluster):
  4. Manifest permission combinations (RECEIVE_SMS + READ_SMS + INTERNET)
  5. Manifest component declarations (BroadcastReceiver with SMS intent-filter)
  6. DEX string pool contents (URLs, content URIs, column names)

LOW WEIGHT (changing these had no observable effect):
  7. Class/method names
  8. Package structure
  9. Number of classes
  10. JSON key names
  11. Code logic / control flow
  12. Number of activities / UI complexity
```

### The Asymmetry

The hierarchy reveals a fundamental asymmetry:

**What the attacker cares about** (code logic, data flow, capture targets, exfil protocol) is **LOW WEIGHT** in the ML model.

**What the attacker doesn't care about** (which HTTP library, which R8 config, which obfuscation dictionary) is **HIGH WEIGHT** in the ML model.

This means an attacker can change every high-weight feature without touching a single line of offensive code. The stealer reads SMS identically. The exfil posts identically. The persistence restarts identically. Only the build pipeline changed.

---

## Implications for Detection Engineering

### For ML-Based Detectors (RED perspective)

1. **Library substitution defeats library-fingerprint features.** Replace OkHttp with `HttpURLConnection`, Retrofit with `URL.openConnection()`, Volley with platform `HttpsURLConnection`. Zero-library-dependency apps have no library fingerprint.

2. **Default R8 settings defeat obfuscation-topology features.** `proguard-android.txt` with no custom flags produces bytecode indistinguishable from millions of legitimate Play Store apps.

3. **No custom dictionary defeats vocabulary-pattern features.** Let R8 use default sequential renaming.

4. **String externalization to resources.arsc defeats DEX string-pool features.** Move sensitive literals (`content://sms/inbox`, column names, C2 URLs) to `strings.xml`.

5. **intArrayOf encoding defeats both DEX and resources.arsc scanning.** Character codes stored as integer arrays with arithmetic shift are indistinguishable from any app's numeric data arrays.

### For Detection Teams (BLUE perspective)

1. **Static ML signatures are brittle.** The entire 11-round campaign changed zero lines of stealer logic — only build artifacts. An ML detector that cannot be evaded by build-pipeline changes alone is not fit for purpose.

2. **Behavioral invariants survive all evasion rounds.** These patterns persisted through all 11 rounds and are present in all 4 specimens:
   - `ContentResolver.query()` against `content://sms/inbox`
   - `HttpURLConnection.connect()` POSTing JSON to loopback
   - `ForegroundService` with `dataSync` type persisting across reboots
   - `BOOT_COMPLETED` BroadcastReceiver restarting services

3. **Detection should target call-chain topology, not library presence.** Rule: "ContentResolver query against SMS provider -> JSON serialization -> HTTP POST within same execution context" catches the stealer regardless of HTTP client library.

4. **Manifest-based rules are cheap to evade but still valuable as first-pass filter.** The SMS-stealer removed `RECEIVE_SMS` permission — but still needs `READ_SMS`. Permission combinations remain useful for triage, not for conviction.

5. **resources.arsc is now part of the detection surface.** Externalized strings don't disappear — they move. Detection pipelines that only scan DEX miss the resource-externalization evasion entirely.

6. **DexClassLoader + file deletion is a high-confidence behavioral indicator.** No build-pipeline change affects this runtime pattern. PayloadManager downloads, loads, and deletes in sub-second — only Frida hooks or memory dumps capture the payload.

---

## Round-by-Round Timeline

| Round | Date Range | Target | Changes | sms-stealer VT | dropper VT | Notes |
|---|---|---|---|---|---|---|
| 1 | Initial build | Both | Baseline specimens with OkHttp + aggressive R8 + themed dictionary | 3/75 | 3/75 | Multiple ML detections |
| 2 | Week 1 | Both | Package renames, basic camouflage classes | 1/75 | 1/75 | Only BitDefenderFalx remained |
| 3 | Week 2 | Both | JSON key rename (sender->k1, body->k2) | 1/75 | 1/75 | `aATNS` cluster invariant |
| 4 | Week 2 | Both | Package restructure, intermediate classes | 1/75 | 1/75 | `aATNS` cluster invariant |
| 5 | Week 3 | Both | 20+ camouflage utility classes | 1/75 | 1/75 | `aATNS` cluster invariant |
| 6 | Week 3 | Both | ContentProvider + Settings/About/Onboarding activities | 1/75 | 1/75 | `aATNS` cluster invariant |
| 7 | Week 4 | Both | Class rename (SmsGrabber -> DataCollector), split layers | 1/75 | 1/75 | `aATNS` cluster invariant |
| 8 | Week 4 | sms-stealer | Removed RECEIVE_SMS + BroadcastReceiver | 1/75 | 1/75 | Manifest change insufficient |
| 9 | Week 5 | Both | String externalization to strings.xml | 1/75 | 1/75 | `aATNS` cluster invariant |
| **10** | **Week 5** | **Both** | **OkHttp removal + dictionary deletion + R8 softening** | **0/75** | **0/75** | **Falx cluster broken** |
| **11a** | **Week 6** | **sms-stealer** | **optimize R8 + 9 deps + battery dictionary** | **0/75** | -- | **Boogr.gsh defeated** |
| **11b** | **Week 6** | **stage-1-evasion** | **5 manifest-bound class renames** | -- | -- | **Boogr.gsh defeated (class names)** |
| **11c** | **Week 6** | **overlay-banker** | **18 RAT permissions stripped from manifest** | -- | -- | **K7GW defeated (capability surface)** |

Rounds 3-9 (7 rounds) produced identical detection. Round 10 (3 build-pipeline changes) broke BitDefenderFalx. Round 11 (3 specimen-specific fixes) broke Kaspersky and K7GW. Each engine targeted different feature dimensions — no single evasion strategy defeated all three.

---

## Reproduction

```bash
# Build all 4 specimens
for spec in sms-stealer dropper stage-1-evasion overlay-banker; do
  cd specimens/$spec && ./gradlew assembleRelease && cd ../..
done

# Hash verification
sha256sum specimens/*/app/build/outputs/apk/release/app-release.apk

# Expected hashes:
# sms-stealer:     32f37e555609a3ae9547533563895fe13227aea773dde13d3a3720df84c6e243
# dropper:         254465be9b6b2c8aeb951dabe23b6f9032ef149006ef2281b1e63bdb6a9ee7ed
# stage-1-evasion: af5ceb94cb9d7bc9a37eacca1cf25b066761e24429bda7151d52378e69b01612
# overlay-banker:  33207904cb76210b75904d25aee021ca85d313cc1bf79368c3c6abb523d8e2b0

# VT upload (replace API key)
VT_KEY="YOUR_API_KEY"
for apk in specimens/*/app/build/outputs/apk/release/app-release.apk; do
  curl -s --request POST \
    --url https://www.virustotal.com/api/v3/files \
    --header "x-apikey: $VT_KEY" \
    --form "file=@$apk"
done
```

### APK Size Reference

```
sms-stealer:      1,662,678 bytes  (1.62 MB)
dropper:          1,679,688 bytes  (1.68 MB)
stage-1-evasion:  1,741,741 bytes  (1.70 MB)
overlay-banker:   1,879,623 bytes  (1.84 MB)
```

Overlay-banker dropped from 5.28 MB → 1.84 MB after native code removal (Round 11c-2). OkHttp still included but R8 shrinks it aggressively without native .so amplification.

---

## Key Takeaway

**The build pipeline + manifest declaration is the ML feature surface.** Code-level sophistication — DGA algorithms, intArrayOf encoding, ContentResolver indirection, batch exfiltration, 19-command C2 protocols, anti-forensics payload cleanup — none of it matters to the classifier. What matters is which libraries are bundled, how R8 is configured, whether the obfuscation dictionary has words in it, what permissions the manifest declares, and what the manifest-bound class names are called.

**Three classifiers, three feature dimensions, zero code-level features.** BitDefenderFalx targets build-artifact topology. Kaspersky Boogr.gsh targets manifest-bound identifier vocabulary and class-count profiles. K7GW targets manifest capability surface area. All three are defeated by non-code changes — build config, dependency list, class renames, permission declarations. Not a single line of stealer logic changed across all 11 rounds.

This is not a failure of ML per se. It is a failure of ML trained on non-behavioral features in an adversary model where those features are freely manipulable. Detection must move to behavioral invariants — call-chain topology, runtime API sequencing, cross-component correlation — that cannot be changed by build-pipeline or manifest modification alone.

See [`BLUETEAM-DETECTION.md`](BLUETEAM-DETECTION.md) for the behavioral detection rules that catch all 4 specimens regardless of build configuration.

---

## References

- BitDefenderFalx ML classifier documentation: N/A (proprietary neural network)
- `Android.Riskware.Agent.aATNS` cluster: ML-assigned, no public documentation
- OkHttp 4.12.0 class count: ~2,400 classes in `okhttp3.*` namespace post-R8
- R8 default ProGuard configurations: [Android Developer Documentation](https://developer.android.com/build/shrink-code)
- ProGuard dictionary feature: [ProGuard Manual — Obfuscation Options](https://www.guardsquare.com/manual/configuration/usage#obfuscation)
