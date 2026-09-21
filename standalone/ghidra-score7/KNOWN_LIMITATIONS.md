# Known limitations

## PCE

Parallel Conditional Execution is recognized at the instruction-packet level,
but its execution semantics are not fully lowered into ordinary p-code. The
current definition uses an opaque user-defined p-code operation.

This means disassembly can identify the packet while the decompiler cannot
fully reason through its conditional data flow.

## Custom/system operations

Several instructions are intentionally represented by opaque p-code operations
because their architectural side effects are not modeled by the public
permissive execution reference used during implementation.

Known examples include custom-engine/cache/control operations and rotate/custom
engine families for which MAME itself reports an unemulated operation.

## Validation boundary

The exact archived source was compiled and exercised on Ghidra 12.1.2. It has
not yet been validated on the current Ghidra development head.

The archive therefore describes an **experimental processor extension**, not a
complete production-quality architecture implementation.
