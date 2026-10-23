"""Execute the exact patched C++ shift bound, plus integration-source guards.

The native program/CFG tests are the registered Java acceptance in the local
Ghidra project.  This small native harness tests the arithmetic boundaries of
that same C++ patch without rebuilding the full engine.
"""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATCH_DIR = ROOT / "patches/ghidra-12.1.3"
PATCH = (PATCH_DIR / "native-unresolved-branchind-c.patch").read_text()
JAVA = (ROOT / "ghidra_scripts/SunplusPCMExactShiftRangeTargets.java").read_text()


def _patched_shift_block() -> str:
    """Extract verbatim added C++ arithmetic, not a Python reimplementation."""
    additions = "\n".join(line[1:] for line in PATCH.splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
    anchor = "else if (op->code() == CPUI_INT_RIGHT) {"
    assert additions.count(anchor) == 1
    block = additions.split(anchor, 1)[1]
    # The unified diff reuses two closing braces from original context.
    return block.rstrip() + "\n  }\n}\n"


def test_exact_rightshift_range_native_cpp(tmp_path: Path) -> None:
    compiler = shutil.which("g++")
    if compiler is None:
        pytest.skip("g++ required for native C++ right-shift boundary proof")
    prefix = r'''
#include <cstdint>
#include <limits>
#include <iostream>
#include <stdexcept>
using uintb = std::uint64_t;
using int4 = int;
uintb calc_mask(int4 bytes) {
    if (bytes >= 8) return std::numeric_limits<uintb>::max();
    return (uintb(1) << (bytes * 8)) - 1;
}
struct Varnode {
    int bytes; bool constant; uintb offset;
    int getSize() const { return bytes; }
    bool isConstant() const { return constant; }
    uintb getOffset() const { return offset; }
};
struct PcodeOp {
    Varnode *source; Varnode *count;
    const Varnode *getIn(int index) const { return index == 0 ? source : count; }
};
uintb patched_bound(int bytes, uintb shift, bool constant = true) {
    Varnode source{bytes, false, 0}, countNode{8, constant, shift};
    Varnode result{bytes, false, 0}; Varnode *vn = &result;
    PcodeOp operation{&source, &countNode}; PcodeOp *op = &operation;
    uintb maxValue = 0;
    {
'''
    suffix = r'''
    return maxValue;
}
void require(bool truth, const char *reason) {
    if (!truth) throw std::runtime_error(reason);
}
int main() {
    std::uint64_t checks = 0;
    for (int bytes : {1,2,4,8}) {
        const unsigned bits = bytes * 8;
        require(patched_bound(bytes, 0) == 0, "zero shift must keep full-domain sentinel");
        require(patched_bound(bytes, 8, false) == 0, "variable shift must not narrow range");
        checks += 2;
        for (unsigned shift = 1; shift <= bits + 4; ++shift) {
            uintb expected = shift >= bits ? 1 : (uintb(1) << (bits - shift));
            require(patched_bound(bytes, shift) == expected, "wrong exclusive range bound");
            ++checks;
        }
        require(patched_bound(bytes, std::numeric_limits<uintb>::max()) == 1,
                "overshift must return zero result domain without undefined C++ shift");
        ++checks;
    }
    require(patched_bound(16, 8) == 0, "unsupported wider values must stay conservative");
    const uintb bound = patched_bound(2, 8);
    require(bound == 256, "PCM high-byte domain must contain every value 0..255");
    bool seen[256] = {};
    for (uintb input = 0; input < 65536; ++input) {
        const uintb high = input >> 8;
        require(high < bound, "16-bit input escaped inferred domain");
        seen[high] = true; ++checks;
    }
    for (bool reached : seen) require(reached, "inferred high-byte domain has holes");
    std::cout << "EXACT_SHIFT_NATIVE_PASS checks=" << checks
              << " input_words=65536 selector_values=256\n";
}
'''
    source = tmp_path / "rightshift.cpp"
    source.write_text(prefix + _patched_shift_block() + suffix)
    # MinGW on the hosted Windows runner has no libubsan; retain exhaustive
    # compiled C++ execution there and the UBSAN-instrumented proof elsewhere.
    executable = tmp_path / ("rightshift.exe" if sys.platform == "win32" else "rightshift")
    flags = ["-std=c++11", "-O1"]
    if sys.platform != "win32":
        flags += ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]
    compiled = subprocess.run(
        [compiler, *flags, str(source), "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    tested = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert tested.returncode == 0, tested.stdout + tested.stderr
    assert "EXACT_SHIFT_NATIVE_PASS" in tested.stdout
    assert "input_words=65536 selector_values=256" in tested.stdout


def test_switch_fix_does_not_bypass_failed_recovery_diagnostics() -> None:
    assert "CPUI_INT_RIGHT" in PATCH
    assert "count->isConstant()" in PATCH
    assert "fail_dynamic" not in PATCH
    assert "funcdata_block.cc" not in PATCH
    assert "jumptable.hh" not in PATCH
    assert "data.recoverJumpTable(partial,op,this,mode)" in PATCH
    assert "__ghidra_unresolved_indirect_jump" in PATCH


def test_previous_native_fixes_remain_in_patch_set() -> None:
    pointer = (PATCH_DIR / "native-word-addressed-ptradd-guard.patch").read_text()
    loop = (PATCH_DIR / "native-explicit-selfloop-c.patch").read_text()
    assert "elementBytes % unitBytes != 0" in pointer
    assert "explicitSelfJump" in loop
    assert "backedge->code() == CPUI_BRANCH" in loop
    assert "backedge->getAddr() == bb->getStart()" in loop
    assert "if (!explicitSelfJump)" in loop


def test_java_verifies_actual_tables_and_all_original_target_values() -> None:
    for token in ("getJumpTables()", "getSwitchAddress()", "getCases()",
                  "cases.length==256", "actual.equals(expected)",
                  "tables.length==4", "high<256", "getExecutableSHA256()",
                  '"SHA-256"', "runtime_mode_subset=UNKNOWN"):
        assert token in JAVA, token
    for forbidden in ("writeOverride(", "setFlowOverride(", "setBytes(",
                      "startTransaction(", "addMemoryReference("):
        assert forbidden not in JAVA, forbidden
