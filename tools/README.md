# Tools Directory

Utility scripts and tooling for the Ghidra MCP Server project.

## What's here

```
tools/
├── setup/         # Project setup, build, deploy, version-bump CLI
│                  #   python -m tools.setup --help
└── (CLI utilities live in fun-doc/ now — see below)
```

## Sunplus DSP SDK candidate

[`sunplus_sdk/`](sunplus_sdk/README.md) provides a local assembly/link SDK,
Python API, strict ELF validation and documentation for the associated Ghidra
PM24/DM16 loader. Run `python -m tools.sunplus_sdk --help` for its public CLI.
`validation/build_sunplus_sdk.py` packages pinned tool sources and a separate
Ghidra 12.1.3 candidate; `validation/sunplus_adsp_roundtrip.py` compares existing
Analyzer instruction listings with the reference assemblers or SDK dialect.
These build utilities do not connect to or mutate an Analyzer project.

The SDK is an assembly toolchain candidate, not a C compiler, flash writer or
accepted Sunplus hardware model. Build/container tests and instruction-byte
matches do not establish complete P-code or saved-program semantic coverage.

## Local DSP diagnostic accounting

`validation/sunplus_warning_audit.py` compares two saved, complete Analyzer C
exports without connecting to Ghidra. It independently counts **warning-owning
functions** and **individual diagnostic occurrences**, checks every C file
against its `index.psv`, and rejects newly introduced warning occurrences even
if another warning disappeared or the total line count stayed constant.

Run with `--before label=/path/to/C/export --after label=/path/to/C/export`.
The command returns a nonzero status for newly introduced diagnostics, and
`--output` saves an auditable JSON delta. Do not compare different native
function denominators. A repeated message in one function counts as multiple
lines but only one warning-owning function.

This audit measures decompiler diagnostics, not Sunplus hardware correctness.
It does not suppress messages or modify local or canonical Analyzer projects.

## Looking for the function-documentation CLI?

Three older scripts (`scan_undocumented_functions.py`,
`scan_functions_mcp.py`, `document_function.py`) used to live here.
They were archived to
[`docs/archive/legacy-tools/`](../docs/archive/legacy-tools/) in v5.10
because **`fun-doc/` does the same job, much better**:

| What you used to run | Now run |
| --- | --- |
| `tools/scan_undocumented_functions.py` | The fun-doc dashboard's "Worker" tab, or `python fun-doc/fun_doc.py --scan` for a one-shot inventory. |
| `tools/scan_functions_mcp.py` | Same — `fun-doc/` ranks candidates continuously with proper state. |
| `tools/document_function.py --function FUN_401000` | `python fun-doc/fun_doc.py --manual --address 0x401000` (single function), or just let the worker pick up the next candidate. |

`fun-doc/` adds state persistence (`state.db`), run-history tracking
(`runs.jsonl`), parallel workers with watchdog/heartbeat, the
completeness scoring rubric, provider routing/fallback, the web
dashboard, block-reason capture, and the library-code detector — all
the things the legacy scripts couldn't do.

## Setup CLI

The `setup/` package is the actively maintained tooling. Use it for
every build/deploy/release flow:

```bash
# show all subcommands
python -m tools.setup --help

# common ones
python -m tools.setup build
python -m tools.setup preflight      --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup deploy         --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup bump-version   --new 5.10.0
python -m tools.setup verify-version
```

See [`CLAUDE.md`](../CLAUDE.md) → **Build & Deploy** for the full
workflow including the Gradle alternative.

## Adding a tool

If you have a one-off script that genuinely doesn't fit inside
`fun-doc/`, `tools/setup/`, or `ghidra_scripts/`, drop a standalone
file here with a clear docstring and add a row to the table above.
Most of the time, though, the right home for new utility code is one
of those three existing locations.

---

Analyzer-facing tools connect to Ghidra MCP Server via HTTP (default:
`http://127.0.0.1:8089`).
