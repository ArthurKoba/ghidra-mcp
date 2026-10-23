"""Independent syntax-adapter guards; matching counts are not hardware proof."""
import importlib.util
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sunplus_adsp_roundtrip", ROOT / "tools/validation/sunplus_adsp_roundtrip.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize(("source", "expected"), [
    ("LDI AR,0x0", "ar = 0x0;"),
    (" AR = AY0", "ar = ay0;"),
    ("AR = AY0", "ar = pass ay0;"),
    ("IF EQ AR = AY0", "if eq ar = pass ay0;"),
    ("IF GT AR = 0x0040 - 1", "if gt ar = pass (0x0040 - 1);"),
    ("AF = 0 + 1,AY1 = DM( I0 ,M2 )", "af = pass (0 + 1),ay1 = dm( i0 ,m2 );"),
    ("AR = 0 - AR", "ar = -ar;"),
    ("MR = MX0 * 0", "mr = 0;"),
    ("MR = MR + MX0 * 0 (RND)", "mr = mr (rnd);"),
    ("DMREAD AR,0x3f26", "ar = dm(0x3f26);"),
    ("DMWRITE I4,M5,AR", "dm(i4,m5) = ar;"),
    ("SAT_MR", "if mv sat mr;"),
])
def test_notation_preserves_instruction_class(source, expected):
    assert MODULE.normalize(source) == expected


def test_adapter_does_not_rewrite_genuine_decoder_mismatches():
    assert MODULE.normalize("DIVQ MR2") == "divq mr2;"
    assert MODULE.normalize("DIS_G_MODE") == "dis g_mode;"
    assert "pdreg" in MODULE.normalize("PDReg = PM( I5 ,M5 ),MX0 = DM( I1 ,M3 )")


def test_no_machine_word_fallback_or_arbitrary_source_injection():
    for text in ("nop; nop", ".byte 0;", "#include x", "", "nop\nrts"):
        with pytest.raises(ValueError):
            MODULE.normalize(text)


def test_reference_verified_division_and_mode_selection():
    model = (ROOT / "processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec").read_text()
    for code, register in enumerate(("AX0", "AX1", "AR", "MR0", "MR1", "MR2", "SR0", "SR1")):
        assert f"is xop3={code} & {register}" in model.split("DivX:", 1)[1].split("JumpAddr:", 1)[0]
    assert "DivY: AY1 is yop2=1" in model and "DivY: AF  is yop2=2" in model
    divs = model.split(":DIVS", 1)[1].split(":DIVQ", 1)[0]
    assert "AF=(upper<<1)|(oldq>>15);" in divs
    assert "AY0=(oldq<<1)|zext(AQF);" in divs
    assert "DivX=newupper" not in divs
    assert ":DIS_BIT_REV is whole24=0x0c0080 { MSTAT = MSTAT & 0xfffd; }" in model
    assert ":ENA_BIT_REV is whole24=0x0c00c0 { MSTAT = MSTAT | 0x0002; }" in model
    assert ':"" PDReg "=" "PM("' in model


def test_saved_analyzer_listing_accepts_both_metadata_schemas(tmp_path) -> None:
    import json
    original = {
        "program": "fixture.bin", "source_sha256": "ab" * 32,
        "decoded_instructions": 1,
        "instructions": [{"address": "PM:0100", "word_address": 0x100,
                          "bytes": "0a000f", "text": "RTS"}],
    }
    old = original | {"version": 10, "path": "/fixture.bin", "native_functions": 1}
    new = original | {"saved_version": 10, "program_path": "/fixture.bin", "native_total": 1}
    for name, metadata in (("old", old), ("new", new)):
        path = tmp_path / f"{name}.listing.json"
        path.write_text(json.dumps(metadata))
        verified = MODULE.checked_listing(path)
        assert verified["version"] == 10
        assert verified["path"] == "/fixture.bin"
        assert verified["native_functions"] == 1
        assert verified["instructions"] == original["instructions"]
    wrong = old | {"saved_version": 11}
    path = tmp_path / "contradiction.listing.json"
    path.write_text(json.dumps(wrong))
    with pytest.raises(ValueError, match="Contradictory"):
        MODULE.checked_listing(path)


def test_transient_assembler_os_error_does_not_poison_persistent_cache(tmp_path, monkeypatch):
    """Missing executable/path is infrastructure, not an ISA incompatibility."""
    import subprocess
    tool = tmp_path / 'as2181'
    tool.write_bytes(b'stub assembler bytes')
    linker = tmp_path / 'unused'
    cache = tmp_path / 'cache'
    source = 'rts;'
    def fail(_argv, _cwd):
        raise OSError('temporary external tool failure')
    monkeypatch.setattr(MODULE, 'execute', fail)
    old = MODULE.assemble(source, 'as2181', tool, linker, cache)
    assert old.state == 'TOOL_ERROR'
    assert not list(cache.rglob('result.json'))
    called = []
    def success(argv, cwd):
        called.append(argv)
        (cwd/'instruction.exe').write_bytes(b'0A000F\n')
        return subprocess.CompletedProcess(argv, 0, '', '')
    monkeypatch.setattr(MODULE, 'execute', success)
    new = MODULE.assemble(source, 'as2181', tool, linker, cache)
    assert new.state == 'ENCODED' and new.machine_hex == '0a000f'
    assert len(called) == 1 and len(list(cache.rglob('result.json'))) == 1
    same = MODULE.assemble(source, 'as2181', tool, linker, cache)
    assert same == new and len(called) == 1
