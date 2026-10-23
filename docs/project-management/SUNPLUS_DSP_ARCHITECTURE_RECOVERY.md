# Sunplus Audio DSP: architecture recovery versus saved-program preparation

Status: LOCAL PROTOTYPE, 2026-10-14. No canonical Analysis migration,
deployment, Git commit or native-hardware equivalence is implied.

## Separation of responsibilities

The SLEIGH language in processors/SunplusSPHEAudioDSP describes the ISA:
24-bit PM instructions, 16-bit word-addressable DM, register state, flags,
ALU/MAC, shifter and the decoded meaning of DO/CE. It is not an assembler
and does not by itself change previously persisted instructions/P-code
in a saved Ghidra program.

Four architecture-derived GhidraScript analysis passes live in ghidra_scripts.
None contains target-image PM loop sites, DM word manifest addresses,
hard-coded function names or precomputed per-profile accepted counts.

1. SunplusDSPStructuralRecovery.java
   - Infer DO intervals/endpoints directly from native PM instruction operands,
     DO fallthrough, owner function and P-code branch destinations.
   - Recover only non-nested incomplete CE ends with complete, unambiguous
     instructions and without unproved counter/call hazards.
   - Treat BOTH the containing and the contained DO as nested. An outer DO
     is not eligible for the non-nested pass even if its own nesting depth is 1;
     the nested pass must prove the shared hardware counter/stack contract.
   - Explicitly classify already-correct direct, still-indirect, nested,
     crossing, invalid and unsafe loops. Never invent the target of BRANCHIND.

2. SunplusDSPNestedLoopRecovery.java
   - Derive depth-two nesting from strict interval containment.
   - Verify that inner DO has a preceding native CNTR load and that the
     corresponding SLEIGH context saves the outer counter.
   - Prove any callee is a finite leaf with exactly one RTS, no DO/CNTR
     mutations, no subsequent calls and no synthetic loop-stack writes.
   - Recover the distinct inner and outer direct CE targets and preserve
     their separate count contexts; reject ambiguous/multi-child/deeper
     nested loops and any C/warning regression.
   - The bounded call proof does not implement or validate the whole real
     16-deep shared PC stack.

3. SunplusDSPDmWidthRecovery.java
   - Read Ghidra-generated C, find undersized global DM labels tied to
     a decompiler overlap warning, and validate the original Ghidra
     symbols, existing data width and mapping.
   - If decompilation elides a conflicted label, inspect native P-code
     constant-address DM LOAD/STORE whose access width is exactly 2 bytes.
   - Set only proven 16-bit DM cells to undefined2, preserving both default
     DAT_DM labels and manually named user symbols. Allocate only the exact
     missing uninitialized DM runs. Never populate unknown values or guess
     RAM/MMIO/volatile ownership.

4. SunplusDSPHandshakePollRecovery.java (RUSH 25 audit-only candidate detector)
   - Read C warnings and native PM/DM operations to identify candidate polling
     loops. A preceding write and a backward branch do NOT prove a concurrent
     writer, dominance, or a complete asynchronous handshake.
   - The former automatic `apply-safe` path is now explicitly disabled before
     candidate discovery. It must not set volatile based only on this pattern.
   - Fixed the DM address-unit defect in the unvalidated prototype: a native
     LOAD/STORE constant is a word address, whereas AddressSpace.getAddress(long)
     accepts a byte offset. Multiply by the addressable unit size and check the
     inverse conversion before using the address. No program had been patched
     with the defective prototype by this agent.
   - Actual qualifier/type repair requires a separately saved behavior contract
     and a bounded Analyzer MCP proof. Physical ownership and execution remain
     separate from a static C correction.

## Native inline coefficient tables (local-only)

`SunplusDSPInlineCoefficientTableRecovery.java` accepts an explicit image hash,
owner, table start, entry count and existing store/RTS join. It verifies every
encoded direct JUMP and each converging `LDI AR`, `LDI SR1`, immediate OR-shift
case before recovering missing instructions and extending the existing body.
`audit` performs no mutation; `apply-safe` requires a clean isolated local
project and a recoverable baseline; `readback` verifies the saved result.

This pass proves native layout and code ownership, not the possible values of
an indirect selector. It adds no computed-jump references or flow overrides,
changes no source bytes, and rejects new diagnostic occurrences while allowing
verified reductions after correct recovery. The caller must save outside the script transaction and independently
reopen the local project. Full-function C acceptance remains a separate gate.
Data-path width and dynamic selector bounds remain unresolved when no primary
evidence establishes them. Neither source installation nor this local pass
permits changes to the main Analyzer project.

## Operating contract

Each pass defaults to audit (no mutation). For the first three passes,
apply-safe is an explicit action for an independently backed-up private Ghidra
GZF. The polling detector remains audit-only and rejects apply-safe. It first checks language,
program evidence and native function topology; a transaction applies only
the derived changes. Acceptance rejects modified initialized firmware bytes,
changed function identities/boundaries, C failures, increased warnings,
lost C loops and unexpected register/data classifications. Unknown cases
remain unmodified and are recorded as gaps.

Run against an isolated project using Ghidra analyzeHeadless with
-noanalysis -scriptPath ghidra_scripts and -postScript followed by one of
the three script files and audit. For a copy with prior analysis artifacts
and a verified backup, use apply-safe in phases and save, then independently
reopen and rerun audit. Finish with the separate strict checker
SunplusDSPFullCorpusAcceptance.java strict OUTPUT_DIR EXPECTED_FUNCTION_COUNT.
Strict CE checks also reject direct PM destinations that miss the decoded DO
fallthrough. Computed `BRANCHIND` loop targets remain separately measured as
unresolved; external-branch shape is never proof of their actual destination.

These passes are currently explicit GhidraScripts, NOT automatically
installed analyzers in the ghidra-mcp production process. The resident
srvdsp wrapper still has a separate firmware-window load contract handled
by SunplusSrvdspPostProcessor. Do not silently apply codec semantics to
that resident handoff.

## Repeatable local acceptance

- Non-nested CE pass: on a saved 165-function AC-3 checkpoint before two
  missing CE ends, found both missing DOs without target offsets and
  restored two C loops. No new warnings; saved transaction.
- DM pass: on separate saved checkpoints without applying explicit DM
  address lists, recovered AC-3 9/9, PCM 47/47, AUX 287 directly justified
  cells (including 27 user labels) and DTS 318 native-proven cells. The
  AUX residual missing C identifier was resolved by a native P-code LOAD,
  not by injecting a target address. Source bytes and C DO counts held.
- Nested pass: found two depth-two DTS loop pairs and proved a leaf callee
  preserves synthetic count/loop state. Restored four nested C loops
  with warnings 9 to 1 in that owner, without PM address tables.
- On the composed saved DTS checkpoint, a NEW read-only invocation of all
  three passes reports no further changes, and the independent strict
  full-corpus checker passes 103/103 C, 76/76 external-branch CE shape,
  0 warnings, with no bad instruction C. This is not silicon proof.

Logs, isolated projects and source-byte hashes are held in the
local-rush24-universal-analyzer-20261014 workspace, not in this Git checkout.
Previously manually accepted GZF artifacts remain comparison baselines.

## RUSH 25 incremental safety checks (source-level only)

- Generic DO/CE classification now marks both inner and outer intervals as
  `NESTED`; the structural pass cannot repair an outer loop without the
  separate CNTR/stack provenance check.
- Strict corpus acceptance rejects direct CE PM destinations that fail to
  match the decoded DO fallthrough. Indirect targets are counted separately,
  never asserted as proven target equality.
- Validation: 35 focused Python tests, compilation of both changed Java
  GhidraScripts against Ghidra 12.1.3, and changed-file whitespace checks
  passed. No canonical Analysis execution, saved GZF regression or runtime
  deployment of these changes has been performed in RUSH 25.

## Open architectural gaps

- A fresh arbitrary raw image still requires loader/image-base detection,
  valid PM/DM memory conventions, function discovery, P-code semantics
  for unobserved instructions and complete instruction-mode state.
- The branch-shape and decompiled-C criteria do not fully validate the
  ADSP-style hardware loop stack, nested CALL/RTS and interrupts.
- Some CE ends legitimately remain BRANCHIND. A direct target requires
  dataflow proof, not a generic replacement.
- PM/DM storage ownership, volatile changes, self-modifying PM,
  peripheral and board effects are not established merely by symbol widths.
- The separate native Ghidra RulePtrArith/RulePtraddUndo patch still
  requires upstream review and runtime deployment before canonical analysis.
- AC-3, PCM and AUX keep non-overlap semantic warnings and are not
  globally strict-accepted. The original pre-analyzed srvdsp wrapper
  was separately accepted as a static resident-handoff model.

## Toward an assembler and a compiler

Build an ISA instruction schema separate from analyzer hints: every
encoding field, operand, condition, register, instruction-word endianness,
PM branch address rule, PM24/DM16 transfer and flag side effect must have
golden machine-byte fixtures. A first assembler milestone is a lossless
decode -> normalize -> encode roundtrip for every observed instruction
bit pattern, including aliases and reserved encodings where well-defined.
Then test semantic equivalence between decoded P-code and an independent
reference emulator/board trace where available. Only after that add
relocation of PM branches, instruction scheduling, shared stack/call
discipline, binary patching with verified checksums and eventually a
register-allocating compiler backend. SLEIGH decoding alone does NOT
provide an encoder or a correct compiler.

## RUSH 25 semantic-warning root-cause triage (saved local C only)

Scope is the reopened **local** GZF C outputs only, not canonical Analyzer
readback. No warning-count reduction is claimed. Avoid a new full-corpus test
until repair candidates are established; do not make bulk state changes while
the canonical Analysis project has outstanding operations.

| Profile | Affected C functions | Grouped warning families | Next evidence boundary |
| --- | ---: | --- | --- |
| AC-3 | 23 | 23 unreachable-block; 14 additionally flagged as do-nothing infinite loop | Read bounded native control flow for common `PM:010C..013C` blocks and actual mailbox polling at `PM:2BF0`; test only proven owner/volatile fixes |
| PCM | 12 | 10 unreachable, 1 indirect-jump/jumptable, 1 infinite-loop | Recover register/index provenance across calls in `PM:02EA` and missing CFG edges in remaining owners |
| AUX | 8 | 6 unreachable, 2 indirect-jump/jumptable | Verify `I4..I7` writes and preservation across `SetResidentAudioOutputBlock` before materializing computed targets |

LIKELY (not confirmed): repeated AC-3 unreachable addresses across 14
independent C functions reflect a shared function-body/CFG reconstruction
problem rather than 14 independent opcode failures. The `PM:2BF0` saved C
collapses the resident acknowledgement polling loop into `while (true)`;
compare the native mailbox read/write/feedback contract before marking any
exact DM location volatile. The DSP cspec currently lists only `PC` and `SP`
as unaffected by calls, so a constant `I4..I7` destination before a mailbox
call does not itself prove the indirect jump remains constant afterwards.
Do **not** globally mark all index registers unaffected, all DM memory
volatile, or all `BRANCHIND` targets direct without native proof.

The strict local pass counts are AC-3 23, PCM 12, AUX 8, DTS 0, resident 0.
These 43 affected functions are **not** 43 distinct root causes. RUSH 25 now
has an audit-only shared-status candidate detector; its former automatic
volatile application was disabled after source review. No whole-corpus warning
delta is claimed. A separate explicit-contract AC-3 metadata experiment restores
one helper with two C messages to zero; persistence/readback remain blocked.

## Assembly SDK and loader boundary (2026-10-15 local candidate)

The reusable build implementation now lives in `tools/sunplus_sdk/`; its README
owns usage, packaging, assumptions and unsupported capabilities. The Ghidra
adapter is `com.xebyte.loaders.SunplusDspElfLoader`, with a strict standalone ELF
container parser. It maps linked PM and DM sections using their distinct word
units; it does not update old instructions or discover all native functions.

The source SDK, rebuilt native tools and distributed package produce identical
synthetic linked ELF/PM/DM outputs. Explicit INC/DEC constant forms and the vendor
NONE alias close the outstanding assembler-notation cases without changing
machine words or suppressing model discrepancies. This does not accept the
processor arithmetic, address generator, call/loop stack or original codec C.

Current SDK gate: 68/68 focused Python tests and 23/23 Java tests, including a
real symbol-preserving SDK ELF, passed. The language and loader are packaged as
Ghidra 12.1.3 candidates. No C frontend, runtime ABI, production deployment or
canonical model migration is claimed. A read-only Analyzer environment probe
was provider-blocked; it is not evidence of an Analyzer/runtime test failure.
Target-specific coverage and the pending migration remain managed in Issue #43,
with canonical saved Analyzer evidence required for any semantic promotion.
