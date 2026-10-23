"""Source guards for the native-layout recovery; runtime proof is local Analyzer C/save/readback."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ghidra_scripts/SunplusDSPInlineCoefficientTableRecovery.java").read_text()


def test_recovery_is_explicitly_scoped_and_source_checked() -> None:
    for token in ("mode image_sha256 owner table_start entry_count join", "getExecutableSHA256()",
                  "args[1].equals(imageHash())", "GHIDRA_MCP_PROJECT_ROOT", "toRealPath()",
                  "Preserve pre-existing unsaved work", "count <= 256"):
        assert token in SOURCE, token
    for token in ("pcm-profile.bin", "PM:0320", "PM:02ea", "PM:0397"):
        assert token not in SOURCE, token


def test_native_layout_not_selector_guess_drives_recovery() -> None:
    for token in ("instruction.getFlows()[0]", "target.equals(expected)",
                  "branch.getFlows()[0].equals(join)", "Unknown mode",
                  "Selector domain and dynamic entry reachability UNKNOWN"):
        assert token in SOURCE, token
    for forbidden in ("addMemoryReference(", "setFlowOverride(", "JumpTable.writeOverride",
                      "setBytes(", "setByte(", "setRemoveUnreachable("):
        assert forbidden not in SOURCE, forbidden


def test_apply_preserves_ownership_diagnostics_and_bytes() -> None:
    for token in ("Foreign function owns table/case", "getDefinedDataContaining(at)",
                  "getInstructionContaining(at)", "command.enableCodeAnalysis(false)",
                  "indirectReferences(function).equals(references)",
                  "requireNoNewWarnings(beforeC, c(function))", "otherFunctions(function).equals(others)",
                  "getNumInstructions() == nativeBefore + missing", "endTransaction(tx, commit)"):
        assert token in SOURCE, token


def test_saved_readback_is_distinct_from_staging() -> None:
    for token in ("caller_save_required=true", 'mode.equals("readback")', "missing == 0",
                  "function.getBody().equals(body)", "Local structural proof not saved",
                  "Preserve conflicting existing structural proof"):
        assert token in SOURCE, token
    assert "currentProgram.save(" not in SOURCE


def test_warning_reduction_is_allowed_but_new_diagnostics_are_not() -> None:
    assert "private void requireNoNewWarnings(String beforeC, String afterC)" in SOURCE
    assert "previous.remove(warning)" in SOURCE
    assert '"New C diagnostic: "' in SOURCE
    assert "warnings(c(function)).equals(warnings(beforeC))" not in SOURCE
