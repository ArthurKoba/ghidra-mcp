"""Occurrence-accurate local warnings: separate owner functions and C messages."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "tools/validation/sunplus_warning_audit.py"
SPEC = importlib.util.spec_from_file_location("sunplus_warning_audit", PATH)
assert SPEC is not None and SPEC.loader is not None
import sys
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def export(tmp_path: Path, label: str, warnings: list[str]) -> Path:
    folder = tmp_path / label
    folder.mkdir()
    text = "void f(void) {\n" + "\n".join("  " + warning for warning in warnings) + "\n}\n"
    (folder / "PM_02ea.c").write_text(text)
    (folder / "index.psv").write_text(
        "address|name|status|C_chars|C_do|warning_count|bad_data|reason\n"
        f"PM:02ea|f|OK|{len(text)}|0|{len(warnings)}|0|\n"
    )
    return folder


def test_multiple_warnings_one_function(tmp_path: Path) -> None:
    folder = export(tmp_path, "before", ["/* WARNING: A */", "/* WARNING: A */", "/* WARNING: B */"])
    snapshot = MODULE.read_snapshot("before", folder)
    assert snapshot.native_total == 1
    assert snapshot.warning_functions == 1
    assert snapshot.warning_lines == 3


def test_warning_reduction_is_not_a_regression(tmp_path: Path) -> None:
    before = MODULE.read_snapshot("before", export(tmp_path, "before", ["/* WARNING: A */", "/* WARNING: B */"]))
    after = MODULE.read_snapshot("after", export(tmp_path, "after", ["/* WARNING: A */"]))
    report = MODULE.compare_snapshots(before, after)
    assert report["new_diagnostics"] == 0
    assert report["removed_diagnostics"] == 1
    assert report["warning_functions"] == {"before": 1, "after": 1}
    assert report["warning_lines"] == {"before": 2, "after": 1}


def test_new_warning_detected_even_if_total_does_not_increase(tmp_path: Path) -> None:
    before = MODULE.read_snapshot("before", export(tmp_path, "before", ["/* WARNING: A */"]))
    after = MODULE.read_snapshot("after", export(tmp_path, "after", ["/* WARNING: B */"]))
    report = MODULE.compare_snapshots(before, after)
    assert report["new_diagnostics"] == 1
    assert report["removed_diagnostics"] == 1
    assert report["warning_lines"] == {"before": 1, "after": 1}


def test_repeated_message_increase_detected(tmp_path: Path) -> None:
    before = MODULE.read_snapshot("before", export(tmp_path, "before", ["/* WARNING: A */"]))
    after = MODULE.read_snapshot("after", export(tmp_path, "after", ["/* WARNING: A */", "/* WARNING: A */"]))
    assert MODULE.compare_snapshots(before, after)["new_diagnostics"] == 1


def test_index_disagreement_rejected(tmp_path: Path) -> None:
    folder = export(tmp_path, "before", ["/* WARNING: A */"])
    (folder / "PM_02ea.c").write_text("void f(void) {}")
    with pytest.raises(MODULE.WarningAuditError, match="index says"):
        MODULE.read_snapshot("before", folder)
