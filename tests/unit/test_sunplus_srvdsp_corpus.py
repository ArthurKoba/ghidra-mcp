from __future__ import annotations

from collections import Counter
from hashlib import sha256
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sunplus_sphe_audio_dsp" / "srvdsp.bin"
EXPECTED_SHA256 = "f1c1cd85a647e3669f8bd39ccb75e53ec84a7d6951d17565207155d3e0457d12"
PM_BASE = 0x1800
VECTOR_WORDS = 0x20
CODE_FIRST = 0x20
CODE_END_EXCLUSIVE = 0x95

EXPECTED_CODE_FAMILIES = Counter(
    {
        "type3_dm_direct": 42,
        "type4_alu_mac_dm": 1,
        "type6_dreg_imm": 12,
        "type7_reg_imm": 4,
        "type9_cond_alu_mac": 25,
        "type10_jump_call": 27,
        "type11_do_until": 1,
        "type15_shift_imm": 1,
        "type17_internal_move": 1,
        "type20_return": 1,
        "type29_io_move": 2,
    }
)
EXPECTED_LOCAL_HANDLERS = {
    0x1820,
    0x1824,
    0x1855,
    0x1867,
    0x186F,
    0x187A,
    0x188D,
    0x188F,
    0x1891,
}
EXPECTED_DEFAULT_TARGET = 0x1895


def _words() -> list[int]:
    data = FIXTURE.read_bytes()
    assert len(data) == 1128
    assert sha256(data).hexdigest() == EXPECTED_SHA256
    return [int.from_bytes(data[i : i + 3], "big") for i in range(0, len(data), 3)]


def _family(word: int) -> str | None:
    if word >> 21 == 4:
        return "type3_dm_direct"
    if word >> 21 == 3:
        return "type4_alu_mac_dm"
    if word >> 20 == 4:
        return "type6_dreg_imm"
    if word >> 20 == 3:
        return "type7_reg_imm"
    if word >> 19 == 4:
        return "type9_cond_alu_mac"
    if word >> 19 == 3:
        return "type10_jump_call"
    if word >> 18 == 5:
        return "type11_do_until"
    if word >> 15 == 0x1E:
        return "type15_shift_imm"
    if word >> 12 == 0x0D0:
        return "type17_internal_move"
    if word & 0xFFFFE0 == 0x0A0000:
        return "type20_return"
    if word >> 16 == 1:
        return "type29_io_move"
    return None


def _is_unconditional_jump(word: int) -> bool:
    return ((word >> 19) & 0x1F) == 3 and ((word >> 18) & 1) == 0 and (word & 0xF) == 0xF


def test_srvdsp_fixture_identity_and_shape() -> None:
    words = _words()
    assert len(words) == 376
    assert words[0] == 0x19820F


def test_srvdsp_vector_table_proves_pm_1800_layout() -> None:
    words = _words()
    vectors = words[:VECTOR_WORDS]
    assert all(_is_unconditional_jump(word) for word in vectors)

    targets = {(word >> 4) & 0x3FFF for word in vectors}
    assert targets == EXPECTED_LOCAL_HANDLERS | {EXPECTED_DEFAULT_TARGET}
    assert min(EXPECTED_LOCAL_HANDLERS) == PM_BASE + VECTOR_WORDS


def test_srvdsp_code_region_is_fully_covered_by_supported_instruction_families() -> None:
    words = _words()
    code_words = words[CODE_FIRST:CODE_END_EXCLUSIVE]
    families = [_family(word) for word in code_words]

    unknown = [
        (PM_BASE + CODE_FIRST + index, word)
        for index, (word, family) in enumerate(zip(code_words, families, strict=True))
        if family is None
    ]
    assert unknown == []
    assert len(code_words) == 117
    assert Counter(families) == EXPECTED_CODE_FAMILIES
