# SPHE8202R `srvdsp.bin` reverse-analysis status

Status snapshot: 2026-10-01

This document captures the evidence-backed reverse-analysis state for the recovered Sunplus SPHE8202R audio-DSP wrapper image `srvdsp.bin`. It is intentionally narrower than a full SPHE8202R DSP specification: claims below are limited to the recovered corpus and the behavior proven through the Analysis runtime.

## Corpus identity and layout

- Canonical image size: **1128 bytes**.
- SHA-256: `f1c1cd85a647e3669f8bd39ccb75e53ec84a7d6951d17565207155d3e0457d12`.
- 376 fixed 24-bit PM words.
- Effective PM base: `PM:1800`.
- Vector table: first 32 words, `PM:1800..181F`.
- Local executable wrapper: `PM:1820..1894`, **117 words**.
- Data/coefficient bank: `PM:1895..1977`.

## Vector interface

Vector slots 0..8 select nine local actions; slots 9..31 all land at the default/reserved word `PM:1895`.

| Slot | Target | Recovered action |
| --- | --- | --- |
| 0 | `PM:1820` | `InitializeAndDelegateSrvdsp` |
| 1 | `PM:1824` | `ProcessLevelWindowExtrema` |
| 2 | `PM:1855` | `ProcessWeightedDspAccumulation` |
| 3 | `PM:1867` | `ClearDspDataWindow` |
| 4 | `PM:186F` | `ProcessCountdownRouting` |
| 5 | `PM:187A` | `ProcessThresholdStateAndIo` |
| 6 | `PM:188D` | `SetThresholdStateFromM0AndDelegate` |
| 7 | `PM:188F` | `HandleConditionalReturnOrDelegate` |
| 8 | `PM:1891` | `SetStoredArAndClearState` |
| 9..31 | `PM:1895` | default/reserved landing word (`0x007FFF`) |

## Local action behavior

### `InitializeAndDelegateSrvdsp` (`PM:1820`)

Writes `0x0120` to `DM:0001`, clears AR, then transfers control to resident PM `00E0`.

### `ProcessLevelWindowExtrema` (`PM:1824`)

Maintains the local signed level extrema/window state. Proven behavior includes:

- saves implicit `M0`;
- initializes signed max/min to `0x8000` / `0x7FFF`;
- initializes window/countdown state;
- writes local PM entry word `0x182F` to `DM:0056`;
- initializes a separate long countdown at `DM:0101` to `0x14BD` and decrements it from `PM:182F`;
- reads the resident-provided current level from `DM:0035`;
- updates min/max state;
- tests window count against `0x80`;
- tests absolute level against `0x0200`;
- routes to resident PM `0539` or `05A4`.

### `ProcessWeightedDspAccumulation` (`PM:1855`)

Gate-controlled signed fixed-point accumulation. When `DM:0064 == 0x0765`:

- multiply signed `DM:002C` by weight `DM:00C0`;
- take the high fixed-point contribution;
- multiply `g_sSrvdspCurrentLevel` by `DM:0085`;
- take the high contribution and scale it by 16;
- add both to the previous accumulator `DM:007D`;
- store the result back to `DM:007D`;
- transfer to resident PM `08ED`.

### `ClearDspDataWindow` (`PM:1867`)

Configures the DAG/loop state and clears a `0x160`-word DSP data window. The canonical `DO PM:186C UNTIL CE` is modeled as real `CNTR`-controlled flow; the old opaque `dsp_do_until(...)` representation is no longer used for this proven corpus sequence. Terminal handoff goes to resident PM `0036`.

### `ProcessCountdownRouting` (`PM:186F`)

- writes zero to `IO:003B`;
- decrements shared `g_sSrvdspCountdown` (`DM:0104`);
- expired/non-positive path -> resident `PM:0EBB`;
- active countdown + nonzero route state (`DM:0136`) -> resident `PM:0D04`;
- active countdown + zero route state -> resident `PM:04BC`.

### `ProcessThresholdStateAndIo` (`PM:187A`)

Threshold/hysteresis-style state selection using resident-provided configuration:

- gate `DM:00FE` (local logic active when value is `-1`);
- signed threshold `DM:0086`;
- signed threshold delta/window `DM:00BC`;
- current threshold state `DM:0078`;
- implicit AR/M0/M1.

Updates `DM:0078`, writes AR to `IO:0012`, then transfers to resident PM `092C`.

### `SetThresholdStateFromM0AndDelegate` (`PM:188D`)

Writes implicit `M0` to `DM:0078`, then transfers to resident PM `0398`.

### `HandleConditionalReturnOrDelegate` (`PM:188F`)

Conditional local `RTS`; otherwise terminal transfer to resident PM `10C5`. No local DM state is modified.

### `SetStoredArAndClearState` (`PM:1891`)

Stores AR to `DM:005C`, clears `DM:003D`, then transfers to resident PM `0231`.

## Recovered DM state

The canonical analysis creates an uninitialized `SRVDSP_DM_STATE` backing block over `DM:0000..017F.1`. Proven named state/config includes:

- `g_sSrvdspInitState01` — `DM:0001`;
- `g_sSrvdspLevelMin` — `DM:0027`;
- `g_sSrvdspLevelMax` — `DM:0028`;
- `g_nSrvdspWeightedInput` — `DM:002C`;
- `g_sSrvdspCurrentLevel` — `DM:0035`;
- `g_sSrvdspClearedState` — `DM:003D`;
- `g_nSrvdspLocalPmEntryWord` — `DM:0056` (`0x182F` in this wrapper);
- `g_sSrvdspStoredAr` — `DM:005C`;
- `g_sSrvdspWeightedGate` — `DM:0064`;
- `g_sSrvdspThresholdState` — `DM:0078`;
- `g_sSrvdspWeightedAccumulator` — `DM:007D`;
- `g_sSrvdspSavedM0` — `DM:007F`;
- `g_nSrvdspWeightB` — `DM:0085`;
- `g_nSrvdspThreshold` — `DM:0086`;
- `g_nSrvdspThresholdDelta` — `DM:00BC`;
- `g_sSrvdspWeightA` — `DM:00C0`;
- `g_nSrvdspThresholdGate` — `DM:00FE`;
- `g_nSrvdspLongCountdown` — `DM:0101`;
- `g_sSrvdspWindowCounter` — `DM:0102`;
- `g_sSrvdspCountdown` — `DM:0104`;
- `g_sSrvdspRouteState` — `DM:0136`.

Important cross-action state links:

- `ProcessLevelWindowExtrema -> g_sSrvdspCountdown -> ProcessCountdownRouting`.
- `ProcessThresholdStateAndIo <-> g_sSrvdspThresholdState <- SetThresholdStateFromM0AndDelegate`.
- `DM:00FE`, `DM:0086`, `DM:00BC`, `DM:0136`, weighted-input/weight/gate inputs are read-only within the local wrapper and therefore are resident-provided state/config for this corpus.

## Data bank (`PM:1895..1977`)

### Default vector landing

`PM:1895 = 0x007FFF`; vector slots 9..31 all target this word. No local action starts here.

### Parameter/coefficient bank

`PM:1896..1905` is a parameter/coefficient bank with multiple repeated configuration patterns. Exact product-level meaning remains unproven because consumers reside outside `srvdsp.bin`.

### 4 x 13-word preset table

`PM:1906..1939` contains four consecutive 13-word coefficient/preset records. Seven fields are constant across all records; six fields switch in stepped patterns. Some constant sequences form near-geometric gain-like progressions of approximately `-2.45 dB/step` and `+2.44 dB/step`. Treat this as an evidence-backed coefficient/gain-threshold preset bank; do not assign a specific effect without resident-code evidence.

### Exact Q13 sine windows

Previous working notes described these as FIR tables. That interpretation was corrected after exact mathematical validation.

- `PM:193E..195C`: **31-point Q13 sine window**. For `i=0..30`, every stored coefficient is exactly `round(8192 * sin(pi*(i+1)/32))`. Center `PM:194D = 0x002000`.
- `PM:195F..1975`: **23-point Q13 sine window**. For `i=0..22`, every stored coefficient is exactly `round(8192 * sin(pi*(i+1)/24))`. Center `PM:196A = 0x002000`.
- `PM:195D..195E` and `PM:1976..1977` are zero separators/tail words.

## Coverage and validation boundary

Confirmed local coverage at the end of this analysis pass:

- action discovery: **9/9** local vector actions;
- behavior/decompiler availability: **9/9**;
- low-level local surface: **149/149 operations** (`32 vector words + 117 code words`);
- executable code gaps: **0**. The only formal gaps are the vector table and PM data bank, neither of which is missing executable code;
- DM/state/config: 21 evidence-backed named/typed slots;
- PM data-bank boundaries documented, including the corrected sine-window interpretation.

The remaining uncertainty is outside this blob: resident PM code consumes several state fields and coefficient tables. Product-level names for those consumers cannot be proven from `srvdsp.bin` alone.

## Tooling that enabled the reverse

The custom processor/analyzer work that made this possible is implemented in the same repository:

- `processors/SunplusSPHEAudioDSP/` — SLEIGH processor/language module;
- `src/main/java/com/xebyte/core/SunplusSrvdspPostProcessor.java` — canonical image preparation, rebase, vector action seeding, DM backing, saved-model revision handling;
- `ghidra_scripts/SunplusDSPDecodeSmoke.java` — decode smoke vectors;
- `ghidra_scripts/SunplusSrvdspAnalyze.java` — canonical analysis scaffold;
- `ghidra_scripts/SunplusSrvdspAcceptance.java` — corpus-level runtime acceptance;
- `tests/fixtures/sunplus_sphe_audio_dsp/srvdsp.bin` — canonical fixture;
- `tests/unit/test_sunplus_srvdsp_corpus.py` and `tests/unit/test_sunplus_srvdsp_tooling.py` — corpus/tooling regression tests.

Validated scope is the canonical recovered corpus, not a claim of complete ADSP-218x or full Sunplus DSP ISA compatibility.
