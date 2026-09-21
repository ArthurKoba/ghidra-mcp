# Ghidra SCORE7 processor extension

Experimental Ghidra processor-language support for Sunplus S+CORE 7 / SCORE7.

This extension is preserved from a completed implementation/validation effort
that turned out not to belong to the hardware project that motivated it. It is
kept as an independent processor module because the SLEIGH work is still useful.

## Status

Validated on Ghidra 12.1.2:

- language id: `SCORE7:LE:32:default`
- little-endian 32-bit address space
- mixed 16/32-bit instruction packet decoding
- the architectural PC+2 halfword rule
- ordinary arithmetic/load/store/control-flow decoding
- GCC-style `br r3` and `br! r3` return flow as RETURN p-code
- basic decompiler smoke tests

The language source has **not yet been revalidated against the current Ghidra
development tree**. Do that before proposing an upstream pull request.

## Known limitations

This is not a claim of complete SCORE7 semantic coverage.

- PCE packet execution is represented by an opaque user-defined p-code
  operation rather than fully modeled conditional execution.
- Several custom-engine/system instructions remain opaque user-defined p-code
  operations.
- The permissive MAME SCORE7 implementation used as an execution reference
  also leaves several of those operations unemulated; this module deliberately
  does not invent semantics for them.
- Firmware- or SoC-specific loaders are out of scope.

## Source provenance

The implementation was independently expressed as Ghidra SLEIGH using public
architecture behavior. MAME's BSD-3-Clause SCORE7 implementation was used as a
permissive execution reference; GNU binutils was used as a differential
encoding/decoding oracle.

The extension source itself is distributed under Apache License 2.0; see
`LICENSE`.

## Build

Use a Ghidra-compatible Gradle version and point the build at the Ghidra
installation:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle
```

The resulting extension archive is produced by Ghidra's
`support/buildExtension.gradle`.

Do not commit generated `.sla` files to this archive.

## Upstream preparation checklist

Before opening a focused PR against `NationalSecurityAgency/ghidra`:

1. compile the language against the current Ghidra development tree;
2. run decode vectors covering 16-bit, 32-bit, PC+2, branch/call/return, and
   packet marker cases;
3. retain explicit documentation of incomplete PCE/custom-engine semantics;
4. adapt tests to the upstream processor-module test conventions;
5. submit only the processor module and tests — no ghidra-mcp Docker,
   deployment, or changelog integration.
