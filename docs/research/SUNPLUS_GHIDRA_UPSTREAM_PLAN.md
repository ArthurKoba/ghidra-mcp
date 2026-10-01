# Sunplus SPHE audio-DSP support: upstream contribution plan

This repository now contains a working experimental processor/language implementation and a canonical acceptance corpus for the recovered Sunplus SPHE8202R audio DSP. The next engineering task is to separate the generally useful processor support from ghidra-mcp-specific integration and prepare an upstream contribution to the official Ghidra repository, if the processor is still unsupported there.

## Current implementation assets

- `processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec`
- `sunplus_sphe_audio_dsp.ldefs`
- `sunplus_sphe_audio_dsp.pspec`
- `sunplus_sphe_audio_dsp.cspec`
- smoke/analysis/acceptance scripts under `ghidra_scripts/`
- canonical `srvdsp.bin` fixture and corpus/tooling tests
- runtime integration/post-processing in `SunplusSrvdspPostProcessor`

## Proven architecture/model facts

- big-endian fixed 24-bit PM instruction words;
- PM is word-addressed with three-byte addressable units and needs `alignment=3` for Ghidra 12.1.3 decoding;
- DM/IO modeled as 16-bit word-addressed spaces for the proven instruction forms;
- currently proven encodings are ADSP-218x-compatible forms, but the module intentionally does **not** claim full ADSP-218x coverage;
- canonical corpus exercises instruction families 3, 4, 6, 7, 9, 10, 11, 15, 17, 20, 29;
- proven conditions include NE, GT, LT, ALWAYS and conditional RTS;
- canonical CE hardware-loop sequence has explicit `CNTR` decrement/back-edge semantics;
- resident PM handoffs outside the wrapper are represented as opaque target-preserving userops rather than invented code.

## What should be upstreamed

Prefer upstreaming the reusable processor/language definition, processor/compiler specs, and architecture-focused tests. Keep product-specific automation out of the processor module unless it is demonstrably architecture-generic.

Candidate upstream content:

1. SLEIGH language/spec files under a proper Ghidra processor module.
2. Minimal processor metadata/compiler spec required for the decompiler.
3. Focused instruction decode tests based on legally redistributable small vectors rather than the full product firmware, unless fixture redistribution is acceptable.
4. Documentation clearly distinguishing proven SPHE behavior from unimplemented ADSP-218x/Sunplus variants.

Likely ghidra-mcp-only content:

- canonical raw-image detection by hash/size/signature;
- automatic `srvdsp.bin` PM rebase to `0x1800`;
- seeding exactly nine product vector handlers;
- product-specific `SRVDSP_DM_STATE` backing block;
- saved-program analysis-model migration markers;
- product-specific resident-target list.

These should either remain here or be generalized before proposing upstream.

## Work required before opening an upstream PR

1. Check the current official Ghidra tree for existing ADSP-21xx/Sunplus DSP support and avoid duplicating an existing processor.
2. Read official processor-module contribution conventions and test layout in the current upstream tree.
3. Refactor names/package layout to match upstream conventions.
4. Split architecture-generic SLEIGH from product-specific `srvdsp` scaffolding.
5. Expand decode tests beyond one product wrapper where evidence is available.
6. Document unsupported instruction forms explicitly.
7. Run the upstream processor test/build suite on the target Ghidra version.
8. Prepare a focused PR description with provenance, validation scope, and known limitations.

## Acceptance for the upstream task

Do not call the upstream task complete until:

- official upstream support status has been checked against a current Ghidra checkout;
- reusable vs product-specific code is cleanly separated;
- the processor module builds in an upstream-compatible tree;
- decode/decompiler regression tests pass;
- no claim of complete ADSP-218x/Sunplus support exceeds the evidence;
- an upstream-ready patch/PR is prepared or a concrete upstream blocker is documented.
