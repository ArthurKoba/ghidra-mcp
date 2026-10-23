"""Compare complete saved Analyzer C warnings without conflating functions and lines.

Local/offline only: never contacts, opens, or mutates a Ghidra project.
"""

import argparse
import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


class WarningAuditError(Exception):
    """A saved C inventory or its accounting is invalid."""


@dataclass(frozen=True)
class WarningSnapshot:
    label: str
    native_total: int
    warning_functions: int
    warning_lines: int
    occurrences: Counter[tuple[str, str]]
    c_digest: str


def read_snapshot(label: str, folder: Path) -> WarningSnapshot:
    """Require index/C one-to-one correspondence and occurrence-exact counts."""
    with (folder / "index.psv").open(encoding="utf-8", newline="") as handle:
        records = list(csv.DictReader(handle, delimiter="|"))
    if not records:
        raise WarningAuditError(f"{label}: no indexed native functions")

    occurrences: Counter[tuple[str, str]] = Counter()
    expected_files: set[str] = set()
    warning_functions = 0
    digest = hashlib.sha256()
    for record in records:
        address = record["address"]
        name = address.replace(":", "_") + ".c"
        if name in expected_files:
            raise WarningAuditError(f"{label}: duplicate function {address}")
        expected_files.add(name)
        if record["status"] != "OK" or int(record["bad_data"]) != 0:
            raise WarningAuditError(f"{label}: native C failed for {address}")
        file = folder / name
        if not file.is_file():
            raise WarningAuditError(f"{label}: missing C {name}")
        source = file.read_bytes()
        if not source or int(record["C_chars"]) <= 0:
            raise WarningAuditError(f"{label}: empty C {name}")
        digest.update(name.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(source).digest())
        messages = [line.strip() for line in source.decode("utf-8").splitlines()
                    if "/* WARNING:" in line]
        if len(messages) != int(record["warning_count"]):
            raise WarningAuditError(
                f"{label}: index says {record['warning_count']} warnings for {address}, "
                f"C contains {len(messages)}"
            )
        warning_functions += bool(messages)
        occurrences.update((address, message) for message in messages)
    actual_files = {p.name for p in folder.glob("*.c")}
    if actual_files != expected_files:
        raise WarningAuditError(f"{label}: unmatched C files {actual_files ^ expected_files}")
    return WarningSnapshot(label, len(records), warning_functions,
                           sum(occurrences.values()), occurrences, digest.hexdigest())


def compare_snapshots(before: WarningSnapshot, after: WarningSnapshot) -> dict:
    if before.native_total != after.native_total:
        raise WarningAuditError("Native function denominator changed; do not compare counts")
    newly_added = after.occurrences - before.occurrences
    removed = before.occurrences - after.occurrences
    return {
        "before": before.label,
        "after": after.label,
        "native_total": before.native_total,
        "warning_functions": {"before": before.warning_functions, "after": after.warning_functions},
        "warning_lines": {"before": before.warning_lines, "after": after.warning_lines},
        "added_occurrences": [{"function": a, "message": m, "count": count}
                              for (a, m), count in sorted(newly_added.items())],
        "removed_occurrences": [{"function": a, "message": m, "count": count}
                                for (a, m), count in sorted(removed.items())],
        "new_diagnostics": sum(newly_added.values()),
        "removed_diagnostics": sum(removed.values()),
        "before_c_digest": before.c_digest,
        "after_c_digest": after.c_digest,
    }


def named_directory(value: str) -> tuple[str, Path]:
    label, delimiter, folder = value.partition("=")
    if not delimiter or not label or not folder:
        raise argparse.ArgumentTypeError("Expected label=full-C-export-directory")
    return label, Path(folder)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=named_directory)
    parser.add_argument("--after", required=True, type=named_directory)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    before = read_snapshot(*options.before)
    after = read_snapshot(*options.after)
    report = compare_snapshots(before, after)
    report["status"] = "NO_NEW_DIAGNOSTICS" if report["new_diagnostics"] == 0 else "REGRESSION"
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if options.output is not None:
        options.output.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if report["new_diagnostics"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
