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
