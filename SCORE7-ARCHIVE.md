# SCORE7 experimental processor archive

This branch preserves experimental Sunplus S+CORE 7 / SCORE7 processor work
that was developed while investigating a target later identified as a different
architecture.

SCORE7 is **not** a ghidra-mcp feature or dependency after the main-history
cleanup. The work is kept here because the processor-language implementation may
still be useful as a standalone Ghidra extension or an upstream processor module.

## Preservation points

- Exact validated snapshot tag: `score7-experimental-2026-09-21`
- Tagged commit: `505f862c1a28d08479e1854b5690b9bb4111d9e3`
- Last pre-SCORE7 ghidra-mcp main commit:
  `23ed599fae74cb5e11deddedf0a8e2c036914203`

## What was validated

- Native SLEIGH language id `SCORE7:LE:32:default`.
- Mixed 16/32-bit packet-boundary decoding in live Ghidra.
- `br r3` and `br! r3` modeled as RETURN p-code.
- Compiler specification, processor specification, and language definition.
- Live decompiler smoke tests for ordinary mixed-width code.

## Known limitations

- PCE execution semantics remain opaque to the decompiler.
- Several custom/system instructions remain user-defined p-code operations.
  The permissive MAME reference implementation also leaves these operations
  unemulated, so semantics were not invented.
- This archive does not claim complete ISA semantic coverage.

## Upstream candidate

The reusable processor payload is:

- `ghidra_processors/SCORE7/Module.manifest`
- `ghidra_processors/SCORE7/data/languages/SCORE7.ldefs`
- `SCORE7.pspec`
- `SCORE7.cspec`
- `SCORE7.slaspec`

Before an upstream Ghidra contribution, add upstream-native compile/decode tests
and retest against the current Ghidra development tree.

Do **not** carry these ghidra-mcp-specific pieces upstream:

- Docker image copy/compile integration;
- runtime file-permission workaround;
- ghidra-mcp CHANGELOG entries;
- repository-specific `Score7SleighCompileTest` wiring as-is;
- generated `.sla` files.

## Intended upstream path

1. Retest on the current Ghidra development version.
2. Package as a standalone experimental extension or clean Processor module.
3. Document incomplete PCE/custom-engine semantics explicitly.
4. Discuss scope/acceptance with the Ghidra project before a focused,
   single-purpose pull request.

The current hardware reverse project uses Ghidra as the analysis platform but
does not use SCORE7.
