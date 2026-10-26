# Sunplus SPHE audio DSP — native model and vector runtime evidence

This is a **source release candidate**, not a claim of complete physical DSP
compatibility. The authoritative semantic annotations, execution contracts, and
deployment acceptance live in the saved canonical Analyzer project
`sphe8202r_decoder_p25d80`; isolated local program copies are QA evidence only.

## Files and scope

- `processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec`:
  native instructions, generic CE backedge recovery and opt-in native
  sequencer. The included `sunplus_stack_runtime.sinc` and
  `sunplus_stack_instructions.sinc` represent the 16-slot shared PC stack,
  count and loop stacks, saved status and `RTI` behavior. The default C view
  remains distinct from the opt-in architectural execution view.
- `src/main/java/com/xebyte/sunplus/`:
  native imports, function ownership, DM word boundaries, observable polling,
  condition/flow proof, CE and compound `CALL + CE` contract. Entry point:
  `ProgramScriptService.prepareAndRunAutoAnalysis`.
- `ghidra_scripts/SunplusDSPOriginalVectorEmulatorQA.java`:
  initial source-vector `RTI`, `JUMP`, and reset execution with status
  restoration and stack checks.
- `ghidra_scripts/SunplusDSPOriginalVectorContinuationQA.java`:
  original PM handler execution from the vector `JUMP` to `RTI`, supporting
  bounded polling loops, native DO/CE, CALL/RTS and modeled status transitions.
  A synthetic nonzero value is injected only for a verified
  `DMREAD AR,addr; AR=AR+0; IF EQ JUMP back` sequence; a synthetic zero is
  injected only for a verified `IF NE JUMP back` sequence. No opcode patches.
- `ghidra_scripts/SunplusDSPOriginalDtsCeCallExecutionQA.java` and
  `SunplusDSPFreshCodecCorpusAcceptance.java`: focused P-code and native C
  evidence. The C generator's static-flow projection and execution model must
  be evaluated separately.

The original codec executable images, local copies of the analysis project,
generated `.sla` files, worker logs and sandbox exports are **not** committed.

## Isolated source-proven runtime profile

Each vector script requires a saved, **unchanged**, exact-SHA and function-count
verified program in `/RUSH28-architecture-import-validation/`. Pass the source
SHA-256 and discovered native function count as script arguments, separated
by a space. Example with an already open QA program (Ghidra MCP script root
must contain the versioned Java source):

```text
run_analysis_script(
  program="pcm-source-model-return-tail-rush108-20261026.bin",
  script_name="SunplusDSPOriginalVectorContinuationQA.java",
  args="be1cda3ac614db29818fc68423063ea3820c6033b207442367ccbb7b967242eb 116"
)
```

| Program | SHA-256 | Function count |
| --- | --- | ---: |
| PCM | `be1cda3ac614db29818fc68423063ea3820c6033b207442367ccbb7b967242eb` | 116 |
| AUX | `47ccd79c7868e47dd55c1fdfaf1ccabc315f71c58d6e3f7e3f99c606b1aded2e` | 92 |
| DTS | `6f7af5491b3d174382a9a12a7a96b9cdfdc81b0414a296e620087c25a42df3d1` | 159 |
| AC-3 | `d0a391f61b271c3faac77101271df62729bd643862264fa435421f03365b0c3a` | 180 |

The source SHA-256 here belongs to a Ghidra program's imported executable
identity, **not** to the `*.slaspec` or `*.sla`. The QA folder, exact SHA,
function count and unchanged program state are intentional fail-closed guards.
Do not relax them to make an unrelated import pass. Script code can be
registered through the Analyzer MCP persistent script root; preserve the
script's source hash and record execution output in the canonical project
before claiming canonical evidence.

## Bounded local execution findings (26 October 2026)

| Codec | Native vector | Native handler | PM instructions run | Modeled external states | Full RTI |
| --- | --- | --- | ---: | --- | --- |
| PCM | `0018` | `0BE4` | 160 | `DM:3F04=1`, `DM:3F14=1` | yes |
| AUX | `0018` | `064E` | 2,201 | `DM:3F04=1`, `DM:3F14=1`, `DM:3C14=0` | yes |
| DTS | `0018` | `1B54` | 830 | `DM:3F04=1`, `DM:3F14=1`, `DM:3C14=0` | yes |
| AC-3 | `0018` | `219E` | 11,382 | `DM:3F04=1`, `DM:3F44=1`, `DM:3F14=1`, `DM:3C14=0` | yes |

All four local traces reached `RTI` and restored the injected frame return
address (`PM:0368`), `ASTAT=0x25`, `IMASK=0x2AB`, and zero PC/status
depths. AC-3 additionally has two direct source vector JUMP-to-RTI
one-instruction paths (`PM:0004 -> PM:2B4A` and `PM:0008 -> PM:2B4B`).

The event values are **software fixtures**, not established hardware MMIO
meanings, IRQ names, real timing, all reachable runtime paths or silicon proof.
Native DO and static CALL/CE flow metadata have separate acceptance criteria.
A prior local source C inventory reported 547/547 generated C functions,
548/548 source-derived DO/CE sites, 1,339/1,339 rooted calls and zero C
warnings. These denominators are local snapshots and must be measured anew
on canonical imported programs after deployment.

## Build, CI, and next gate

CI runs for PRs targeting `main`: Java 21 Maven build, Ghidra 12.1.3
SLEIGH compilation/headless fixtures, and Python tests. For a local checkout:

```sh
mvn clean package assembly:single -DskipTests
pytest tests/unit/ -v --no-cov
```

Real original-source vector traces require the above QA program images and
cannot be reproduced from tiny public unit fixtures. If source images are
unavailable, mark that execution dimension **not run** rather than reporting
success.

After a green PR, the independent acceptance step is: deploy the exact
versioned extension and language -> open the **existing** canonical Analyzer
project -> check original image identities -> run complete native analysis and
C generation -> persist verified Java source/scripts in the Analyzer script
root -> execute and annotate precise traces -> save, close/reopen and read back
native code/C/semantics. The saved canonical project, not this document or
local QA project, is the authority. Silicon equivalence remains **UNKNOWN**
until independent hardware/reference comparison.
