"""Universal Sunplus DSP I/M/L addressing invariants, independent of codec offsets.

These Python checks do not replace the Ghidra MCP saved/readback synthetic
P-code acceptance (13 cases), nor assert original silicon execution.
"""
from collections import Counter
from pathlib import Path
import random
import re

SOURCE = (Path(__file__).resolve().parents[2] /
          "processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec")


def effective(index: int, modifier: int, length: int) -> int:
    """Language algorithm: 14-bit circular I/M/L with 16-bit L=0 linear I."""
    if length == 0:
        return (index + modifier) & 0xFFFF
    m14 = ((modifier & 0x3FFF) ^ 0x2000) - 0x2000
    power_of_two = 1 << (length - 1).bit_length()
    base = (index & 0x3FFF) & ~(power_of_two - 1)
    candidate = (index & 0x3FFF) + m14
    if candidate < base:
        candidate += length
    if candidate >= base + length:
        candidate -= length
    return candidate & 0x3FFF


def reference(index: int, modifier: int, length: int) -> int:
    if length == 0:
        return (index + modifier) & 0xFFFF
    power_of_two = 1 << (length - 1).bit_length()
    base = index & ~(power_of_two - 1)
    signed_modifier = ((modifier & 0x3FFF) ^ 0x2000) - 0x2000
    assert base <= index < base + length and abs(signed_modifier) < length
    return (base + (index - base + signed_modifier) % length) & 0x3FFF


def test_circular_ring_reference_for_valid_inputs() -> None:
    randomizer = random.Random(2181)
    for _ in range(25000):
        length = randomizer.randint(1, 0x3FFF)
        bucket = 1 << (length - 1).bit_length()
        base = bucket * randomizer.randrange(0, 0x4000 // bucket)
        index = base + randomizer.randrange(length)
        step = randomizer.randrange(1 - length, length)
        assert effective(index, step, length) == reference(index, step, length)


def test_linear_mode_preserves_original_sixteen_bit_register_arithmetic() -> None:
    for index in range(65536):
        for step in (-32768, -8192, -1, 0, 1, 16384, 32767):
            assert effective(index, step, 0) == (index + step) & 0xFFFF


def test_modulo_selects_length_of_i_not_m() -> None:
    source = SOURCE.read_text()
    families = (("DagL", "g20", "dag_i2", 8),
                ("ModL", "mod_g", "mod_i", 8),
                ("ShiftDagL", "shift_g", "dag_i2", 8),
                ("PmL", "t1_pmi", None, 4),
                ("DmL", "t1_dmi", None, 4))
    for family, group, index, count in families:
        for i in range(count):
            actual = i + (4 if family == "PmL" else 0)
            terms = ([f"{group}={int(actual >= 4)}", f"{index}={actual % 4}"]
                     if index else [f"{group}={actual % 4}"])
            line = f"{family}: L{actual} is {' & '.join(terms)} & L{actual} {{ export L{actual}; }}"
            assert line in source, line


def test_all_postmodification_families_use_one_canonical_semantics() -> None:
    source = SOURCE.read_text()
    macro = re.search(r"macro dsp_dag_postmodify\(target, oldindex, delta, length\)\s*\{([^{}]+)\}", source)
    assert macro
    body = macro.group(1)
    assert "local index14:2 = oldindex & 0x3fff;" in body
    assert "local mod14:2 = delta & 0x3fff;" in body
    assert "local signed14:2 = (mod14 << 2) s>> 2;" in body
    assert "local mode:2 = 0 - zext(length != 0);" in body
    assert "local linear:2 = oldindex + delta;" in body
    assert "target = (linear & ~mode) | (circular & mode);" in body
    # Every DAG post-modifier (including parallel PM+DM and MODIFY) carries L.
    counts = Counter(re.findall(r"dsp_dag_postmodify\((DagI|ShiftDagI|PmI|DmI|ModI),", source))
    assert counts == {"DagI": 58, "ShiftDagI": 11, "PmI": 8, "DmI": 8, "ModI": 1}
    assert "& ModL" in source and "& ShiftDagL" in source


def test_bit_reversed_address_is_not_applied_to_index_postmodification() -> None:
    source = SOURCE.read_text()
    assert "dag1_dm_address(DagI, effective);" in source
    assert "dag1_dm_address(DmI, effective);" in source
    assert "dag1_dm_address(ShiftDagI, effective);" in source
    # The unique post-modifier must receive the original index/step, not the
    # selected bit-reversed *effective* address used for memory access.
    assert "dsp_dag_postmodify(DagI, effective" not in source
    assert "dsp_dag_postmodify(ShiftDagI, effective" not in source
