# Sunplus SPHE audio DSP processor module

Experimental Ghidra SLEIGH language support for the 24-bit audio-DSP program
images used by the Sunplus SPHE8202R family.

The target instruction encoding is ADSP-218x-compatible for the instruction
forms currently implemented here. The module is intentionally named for the
Sunplus target rather than claiming complete ADSP-218x compatibility: the
Sunplus integration and data-memory behavior still contain target-specific
unknowns.

## Current scope

The module has moved beyond the original decode-smoke stage. Its validated scope now includes the complete local instruction corpus used by the canonical SPHE8202R `srvdsp.bin` wrapper plus every instruction word reached by vector-seeded native control flow in the extracted AUX, PCM, AC-3 and DTS codec profiles used for this target. This is reachable-code coverage, not a claim that every 24-bit word in each profile is executable code or that the entire ADSP-218x ISA is implemented.

Architecture/model contract:

- fixed 24-bit big-endian instruction words;
- PM is word-addressed with `wordsize=3` and required `alignment=3`;
- 16-bit DM and IO address spaces;
- explicit PM / DM / IO separation;
- compiler/decompiler model with a synthetic `SP` only for ABI/decompiler support;
- direct and conditional PM flow;
- explicit resident-PM handoffs that preserve the numeric target without fabricating unavailable resident code, enabled only under canonical `srvdsp` wrapper context;
- real `CNTR`-controlled semantics for the proven `DO PM:186C UNTIL CE` loop, likewise scoped to that wrapper context.

Instruction families exercised and modeled by the canonical corpus:

- type 3 — direct DM read/write;
- type 4 — ALU/MAC + DM access forms used by the wrapper;
- type 6 — immediate data-register load;
- type 7 — immediate non-data-register load;
- type 9 — arithmetic/logic forms used by the wrapper;
- type 10 — conditional/unconditional flow and call/jump forms used by the wrapper;
- type 11 — zero-overhead `DO ... UNTIL CE` setup for the proven corpus sequence;
- type 15 — immediate shifter form used by the corpus;
- type 17 — internal register move;
- type 20 — RTS plus codec-observed RTI, with RTI status restoration kept distinct through an explicit userop until the architectural status stack is modeled;
- type 29 — IO-space write form used by the wrapper.

The codec-profile extension now covers the reachable arithmetic/MAC, parallel data/PM/DM access, shifter, stack/mode, direct/indirect flow and internal-register forms exercised by the four extracted decoder profiles. Wrapper-only resident handoffs remain context-scoped. `NEG`/`POS` use the architectural AS input-sign state produced by ABS rather than being approximated through the ALU result-negative flag.

The module remains intentionally named for the Sunplus target. It is **corpus-complete for the recovered SPHE wrapper and zero-gap for the currently reachable control-flow corpus of the four extracted codec profiles**, not a claim that the full ADSP-218x ISA, every word in the profile images, or every Sunplus DSP peripheral semantic is implemented.

The first target regression words remain useful smoke vectors:

| Word | Expected decode |
| --- | --- |
| 0x19820f | JUMP 0x1820 |
| 0x0a000f | RTS |
| 0x80023a | direct DM read into AR from 0x0023 |
| 0x80021a | direct DM read into AR from 0x0021 |
| 0x0a001f | RTI |
| 0x180250 | IF EQ JUMP 0x0025 |
| 0x22e21f | AR = AR - 1 |
| 0x0f02f6 | SR = LSHIFT AR BY -10 (HI) |
| 0x0d00af | AR = SR1 |
| 0x18036f | generic JUMP 0x0036 when wrapper context is not enabled |

## Production validation — 2026-10-02

The completed target-corpus extension is present in `ghidra-mcp/main` commit `5570d8c623ee72e2be9f07eb271d1127fb7d297f` and was deployed to the production Analysis backend through Coolify deployment `#296` on 2026-10-02.

Post-deploy checks:
- production Analysis decoded the previously incomplete AUX entry range with the extended instruction set active;
- canonical `srvdsp.bin` remained at 117/117 local executable words, 9/9 action nodes and 9/9 high-level behavior views;
- the saved board project was re-audited after deployment and retained 21/21 named, typed and documented DM state/config slots;
- AUX/PCM/AC-3/DTS reachable-code acceptance remains zero-gap at 5451/5451, 7787/7787, 10339/10339 and 9651/9651 reached words respectively.

This validates the deployed processor/runtime path for the current target corpus. It does not upgrade corpus coverage into full ADSP-218x compatibility or prove Sunplus DSP clock, cycle budget, memory capacity, peripheral mapping or physical audio-lane ownership.

Board-specific continuation evidence and the current AP1/runtime audio-control contract live in `ArthurKoba/hd-audio-rush-sphe8202r`; keep reusable processor semantics here and target behavior findings in the board repository.

## 24-bit PM C-decompiler recovery (local candidate, 2026-10-09)

A native Ghidra 12.1.3 decompiler regression affected five DTS functions
(`PM:1769`, `25B7`, `266B`, `273E`, `2755`). All five timed out under
full `decompile` even with a longer budget; the `firstpass`, `register` and
`normalize` stages returned promptly. The failure reproduces in standalone
headless Ghidra without MCP, and persists after mapping the missing DM region.

Target-byte ablations establish that removing dynamic PM reads or DM/PM writes
breaks the timeout. Using 16-bit PM loads/stores also unblocks all five, but
**silently drops eight bits and is not a valid DSP model**. The model therefore
keeps PM as a 24-bit word-addressed space and represents the *pure Type-5*
program-memory data accesses with explicit `dsp_pm_load24(address)` and
`dsp_pm_store24(address,word)` p-code userops. The word address remains
16-bit; the read result and write value are full 24-bit words. `DReg4` receives
bits 23..8 and `PX` receives bits 7..0, unchanged from the original encoding.
These operations remain visible in generated C instead of producing a
truncated or invented C translation.

**Local Ghidra 12.1.3 verification** (isolated SDK/project, not production):
SLEIGH compiles; P-code inspection verified 3-byte read/output and write/input
with 2-byte word addresses. From the saved canonical function-entry inventory,
C generation passed DTS 98/98, AUX 61/61, PCM 4/4 and AC-3 25/25; the existing
`srvdsp` acceptance passed 117/117 code words and 9/9 C functions. The new
`ghidra_scripts/SunplusCodecFullCAcceptance.java` provides a repeatable
post-import regression for already-analyzed programs.

**Validation boundary:** `CALL_OTHER` is an *opaque representation* for the
native Ghidra decompiler. Its declared arguments and values preserve the full
24-bit PM access interface, but the userops do **not yet implement PM backing
memory side effects for P-code emulation** and do not model read-after-write
aliasing internally. An emulator/userop library or an upstream decompiler fix
is required before claiming native execution-equivalent P-code. Separately,
the existing canonical Analysis project must refresh saved instruction P-code
under a deployed language model before its old C views can be counted as
repaired. This is local static-C validation, not deployed/runtime/hardware
acceptance or full DSP-algorithm recovery.

## Validation boundary

The language source must compile with Ghidra's support/sleigh compiler during
the Docker build and CI. Runtime acceptance additionally requires importing a
small raw fixture or a preserved target DSP image using
SunplusSPHEAudioDSP:BE:16:default and checking the known regression words.

Do not use this module to infer Sunplus-specific DM width, DSP clock, PM/DM
capacity, coefficient precision, or peripheral mapping. Those remain target behavior-analysis
questions. Current vector-seeded reachable-code acceptance over the preserved target profiles is:

- AUX: 5451 / 5451 reached words decoded, 0 gaps;
- PCM: 7787 / 7787, 0 gaps;
- AC-3: 10339 / 10339, 0 gaps;
- DTS: 9651 / 9651, 0 gaps.

The traversal follows decoded fallthrough and direct-flow edges from the observed vector seeds and stops at unsupported words. It deliberately does not treat unrelated coefficient/data regions as executable coverage. The bounded linear corpus scanner remains available for decoder-development diagnostics, but its output must not be interpreted as a code-completeness percentage.

## srvdsp analysis contract

The canonical 1128-byte `srvdsp.bin` corpus is the decompiler-grade acceptance target for this language module. The recovered image is loaded at PM word address `0x1800`; its first 32 words are a vector table and the locally implemented code occupies `PM:0x1820..0x1894`.

Important Ghidra modeling details:

- PM uses `wordsize=3` and therefore **must use `alignment=3`**. `alignment=1` compiles but Ghidra 12.1.3 will not create instructions for the 24-bit stream.
- Java address APIs operate in byte offsets. Target DSP word addresses must be converted through `AddressSpace.getAddressableUnitSize()` before rebase, disassembly, or function creation.
- The compiler spec exposes a synthetic `SP` in DM solely to satisfy Ghidra stack/decompiler ABI requirements. This does not assert a physical software stack on the DSP; architectural return behavior remains represented by `PCSTACKTOP`.
- Jumps from the wrapper into resident PM outside the image are represented by `dsp_resident_tailcall` userops only when the canonical postprocessor/script sets `srvdsp_wrapper_mode=1`. Generic programs default to normal local jump semantics even if their numeric target matches a wrapper-resident address.
- The canonical `DO PM:186C UNTIL CE` sequence is modeled as real `CNTR`-controlled flow. Decode context marks the proven single-instruction loop end at `PM:186C`; its P-code decrements `CNTR` and emits a conditional back-edge. Other `DO` forms remain intentionally unsupported until observed in corpus.
- Canonical `srvdsp.bin` analysis also materializes an uninitialized `SRVDSP_DM_STATE` block covering `DM:0000..017F.1`, so DSP state can be named and typed without altering PM bytes.
- Vector-seeded action nodes default to `void` return type unless a user-defined signature already exists, preventing generic undefined-return warnings in the behavior layer.
- Saved canonical programs carry a small analysis-model revision marker. Revision 3 applies wrapper context and refreshes only the known resident-handoff / CE-loop instruction words, so older saved state picks up context-scoped decoding without clearing the entire local code region or user action names/comments.

Acceptance requires the canonical corpus to produce zero undefined words in the 117-word local code region, seed all nine vector handlers as functions, successfully generate decompiler output for all nine functions, and expose the `PM:186C` CE loop as real control flow rather than an opaque userop.

## Upstream contribution handoff

The reusable processor support should eventually be separated from MCP/project-specific automation and contributed to Ghidra proper.

Tracking task: `ArthurKoba/hd-audio-rush-sphe8202r#30`.

Upstream extraction should preserve the processor language/compiler-spec semantics and architecture-level regression coverage, while excluding project-specific auto-import/rebase hooks, canonical action names/comments, saved-project revision hooks, and target firmware blobs unless their provenance/licensing is explicitly approved.

The preferred upstream test strategy is synthetic instruction/regression fixtures covering:

- big-endian 24-bit token mapping;
- PM addressable-unit behavior;
- DM/IO access;
- direct/conditional flow, including a generic target that numerically collides with a wrapper-resident handoff;
- arithmetic/condition behavior used by the recovered corpus;
- RTS versus RTI distinction and explicit RTI status-restoration side effect;
- the proven CE-loop counter/back-edge semantics under wrapper context.

An independent reviewer pass is required before treating the implementation as upstream-ready.

