"""Bounded address-output model tests plus SLEIGH source wiring checks.

This tests the specified 14-bit permutation and the source changes, not emitted
P-code or target execution. Those require the separate Analyzer MCP gate.
"""
from collections import Counter
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
LANGUAGE = ROOT / "processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec"


def _network_output(index: int, mstat: int) -> int:
    """Mathematical counterpart of the branch-free address network only."""
    pair = ((index & 0x5555) << 1) | ((index >> 1) & 0x5555)
    quad = ((pair & 0x3333) << 2) | ((pair >> 2) & 0x3333)
    octet = ((quad & 0x0F0F) << 4) | ((quad >> 4) & 0x0F0F)
    word = ((octet << 8) | (octet >> 8)) & 0xFFFF
    address = word >> 2
    mask = (-((mstat >> 1) & 1)) & 0xFFFF
    return (index & (0xFFFF ^ mask)) | (address & mask)


def test_all_fourteen_bit_addresses_match_documented_permutation() -> None:
    for address in range(1 << 14):
        expected = sum(((address >> bit) & 1) << (13 - bit) for bit in range(14))
        assert _network_output(address, 2) == expected
        assert _network_output(address, 0) == address
        assert _network_output(expected, 2) == address


def test_disabled_mode_preserves_existing_sixteen_bit_container_behavior() -> None:
    # Do not turn an address-generator fix into an unproved Sunplus width change.
    for address in range(1 << 16):
        assert _network_output(address, 0) == address
        assert _network_output(address, 0xFFFD) == address


def test_only_mstat_bit_one_controls_the_permutation() -> None:
    for mode in range(256):
        for bit in range(14):
            address = 1 << bit
            expected = 1 << (13 - bit) if mode & 2 else address
            assert _network_output(address, mode) == expected


@pytest.mark.parametrize(("address", "expected"), [(0, 0), (1, 0x2000), (0x2000, 1),
                                                    (0x1000, 2), (0x3FFF, 0x3FFF)])
def test_reference_address_vectors(address: int, expected: int) -> None:
    assert _network_output(address, 2) == expected


def test_address_output_and_index_postupdate_are_separate_contracts() -> None:
    # Four-bit FFT output sequence: normal I increments by 2**(14-4).
    index, step = 0, 1 << 10
    outputs = []
    for _ in range(16):
        outputs.append(_network_output(index, 2))
        index += step
    assert outputs == [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    assert index == 1 << 14  # independent linear arithmetic, not a circular model


def test_sleigh_macro_matches_the_reviewed_branchless_network() -> None:
    source = LANGUAGE.read_text()
    body = re.search(r"macro dag1_dm_address\(index, effective\)\s*\{([^{}]+)\}", source).group(1)
    statements = [line.strip() for line in body.splitlines() if line.strip()]
    assert statements == [
        "local br_pair:2 = ((index & 0x5555) << 1) | ((index >> 1) & 0x5555);",
        "local br_quad:2 = ((br_pair & 0x3333) << 2) | ((br_pair >> 2) & 0x3333);",
        "local br_octet:2 = ((br_quad & 0x0f0f) << 4) | ((br_quad >> 4) & 0x0f0f);",
        "local br_word:2 = (br_octet << 8) | (br_octet >> 8);",
        "local br_address:2 = br_word >> 2;",
        "local br_mask:2 = 0 - ((MSTAT >> 1) & 1);",
        "effective = (index & ~br_mask) | (br_address & br_mask);",
    ]
    assert not re.search(r"\b(if|goto|call|build)\b|\*\[|\bindex\s*=", body)


def test_dag_two_address_tables_do_not_reference_mode_or_reversal() -> None:
    source = LANGUAGE.read_text()
    assert "DagDmAddress: is g20=1 & DagI { export DagI; }" in source
    assert "ShiftDmAddress: is shift_g=1 & ShiftDagI { export ShiftDagI; }" in source
    assert "dag1_dm_address(DagI, effective);" in source
    assert "dag1_dm_address(DmI, effective);" in source
    assert "dag1_dm_address(ShiftDagI, effective);" in source


def test_every_indirect_dm_constructor_uses_its_correct_address_family() -> None:
    source = LANGUAGE.read_text()
    families = {"ShiftDagI": "ShiftDmAddress", "DmI": "DualDmAddress", "DagI": "DagDmAddress"}
    counts: Counter[str] = Counter()
    matched_accesses = 0
    for match in re.finditer(r"(?m)^:[^\n]*(?:\n[^{}]*)?\{[^{}]*\}", source):
        header, body = match.group().split("{", 1)
        memory = re.findall(r"\*\[DM\]:2\s+(\w+)", body)
        if not memory:
            assert not any(name in header for name in families.values())
            continue
        matched_accesses += len(memory)
        family = next((name for name in families if re.search(r"\b" + name + r"\b", header)), None)
        if family is None:
            assert memory[0] in ("addr", "dmaddr") and "addr14" in header
            assert not any(name in body for name in families.values())
            counts["direct"] += 1
            continue
        expected = families[family]
        assert " & " + expected in header
        assert memory == [expected]
        # The effective-address export is used exactly once, only for memory.
        assert body.count(expected) == 1
        assert not re.search(r"(?:DagI|DmI|PmI|ShiftDagI)\s*=.*" + expected, body)
        counts[family] += 1
    assert matched_accesses == source.count("*[DM]")
    assert counts == {"DagI": 38, "DmI": 8, "ShiftDagI": 11, "direct": 4}


def test_layout_and_mode_opcode_identity_are_unchanged() -> None:
    source = LANGUAGE.read_text()
    assert "define space PM       type=ram_space      size=2 wordsize=3 default;" in source
    assert "define space DM       type=ram_space      size=2 wordsize=2;" in source
    assert ":ENA_BIT_REV is whole24=0x0c00c0 { MSTAT = MSTAT | 0x0002; }" in source
    assert ":DIS_BIT_REV is whole24=0x0c0080 { MSTAT = MSTAT & 0xfffd; }" in source
