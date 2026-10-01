# Sunplus SPHE audio DSP processor module

Experimental Ghidra SLEIGH language support for the 24-bit audio-DSP program
images used by the Sunplus SPHE8202R family.

The target instruction encoding is ADSP-218x-compatible for the instruction
forms currently implemented here. The module is intentionally named for the
Sunplus target rather than claiming complete ADSP-218x compatibility: the
Sunplus integration and data-memory behavior still contain target-specific
unknowns.

## Current scope

Version 0.1 establishes the processor model and the instruction forms required
to replace the previous incorrect MIPS import of the project DSP images:

- fixed 24-bit big-endian instruction words;
- word-addressed program memory;
- direct data-memory read/write (ADSP-218x instruction type 3);
- immediate data-register load (type 6);
- immediate non-data-register load (type 7);
- unconditional direct JUMP and CALL (type 10, COND=1111);
- unconditional RTS;
- NOP.

The first target regression words are:

| Word | Expected decode |
| --- | --- |
| 0x19820f | JUMP 0x1820 |
| 0x0a000f | RTS |
| 0x80023a | direct DM read into AR from 0x0023 |
| 0x80021a | direct DM read into AR from 0x0021 |

These words come from the SPHE8202R audio-DSP behavior corpus. They are used
as smoke vectors, not as a claim that the complete ADSP-218x ISA has already
been implemented.

## Validation boundary

The language source must compile with Ghidra's support/sleigh compiler during
the Docker build and CI. Runtime acceptance additionally requires importing a
small raw fixture or a preserved target DSP image using
SunplusSPHEAudioDSP:BE:16:default and checking the known regression words.

Do not use this module to infer Sunplus-specific DM width, DSP clock, PM/DM
capacity, or peripheral mapping. Those remain target behavior-analysis
questions.

## srvdsp analysis contract

The canonical 1128-byte `srvdsp.bin` corpus is the decompiler-grade acceptance target for this language module. The recovered image is loaded at PM word address `0x1800`; its first 32 words are a vector table and the locally implemented code occupies `PM:0x1820..0x1894`.

Important Ghidra modeling details:

- PM uses `wordsize=3` and therefore **must use `alignment=3`**. `alignment=1` compiles but Ghidra 12.1.3 will not create instructions for the 24-bit stream.
- Java address APIs operate in byte offsets. Target DSP word addresses must be converted through `AddressSpace.getAddressableUnitSize()` before rebase, disassembly, or function creation.
- The compiler spec exposes a synthetic `SP` in DM solely to satisfy Ghidra stack/decompiler ABI requirements. This does not assert a physical software stack on the DSP; architectural return behavior remains represented by `PCSTACKTOP`.
- Jumps from the wrapper into resident PM outside the image are represented by `dsp_resident_tailcall` userops. This preserves the handoff target without inventing absent resident bytes and prevents the decompiler from following unmapped PM.
- The canonical `DO PM:186C UNTIL CE` sequence is modeled as real `CNTR`-controlled flow. Decode context marks the proven single-instruction loop end at `PM:186C`; its P-code decrements `CNTR` and emits a conditional back-edge. Other `DO` forms remain intentionally unsupported until observed in corpus.
- Canonical `srvdsp.bin` analysis also materializes an uninitialized `SRVDSP_DM_STATE` block covering `DM:0000..017F.1`, so DSP state can be named and typed without altering PM bytes.
- Vector-seeded action nodes default to `void` return type unless a user-defined signature already exists, preventing generic undefined-return warnings in the behavior layer.
- Saved canonical programs carry a small analysis-model revision marker. Revision 2 refreshes only `PM:186B..186C` once so older saved instruction/context state picks up the CE-loop decoder semantics without clearing user names/comments across the whole module.

Acceptance requires the canonical corpus to produce zero undefined words in the 117-word local code region, seed all nine vector handlers as functions, successfully generate decompiler output for all nine functions, and expose the `PM:186C` CE loop as real control flow rather than an opaque userop.
