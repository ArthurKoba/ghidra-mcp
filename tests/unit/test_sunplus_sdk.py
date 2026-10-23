"""Contract and integration tests for the real SDK assembler/linker boundary."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from tools.sunplus_sdk import MemoryLayout, SdkError, Toolchain, build_image, linked_segments
from tools.validation.sunplus_adsp_roundtrip import normalize


@pytest.fixture
def sdk() -> Toolchain:
    root = os.environ.get("SUNPLUS_DSP_SDK_ROOT")
    if not root:
        pytest.skip("Set SUNPLUS_DSP_SDK_ROOT to exercise native assembler/linker integration")
    tools = Toolchain(Path(root))
    tools.executable("as218x")
    tools.executable("ld21")
    return tools


def source_at(tmp_path: Path, text: str, name: str = "source.dsp") -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def test_memory_layout_rejects_invalid_word_bounds():
    for layout in (MemoryLayout(pm_start=-1), MemoryLayout(pm_start=4, pm_end=3),
                   MemoryLayout(dm_end=0x4000), MemoryLayout(dm_start=0x10000)):
        with pytest.raises(SdkError):
            layout.validate()


def test_toolchain_rejects_missing_tools(tmp_path):
    with pytest.raises(SdkError, match="Missing executable"):
        Toolchain(tmp_path).executable("as218x")


@pytest.mark.parametrize("text", [b"", b"\x7fELF", bytes(64), b"MZ" + bytes(60)])
def test_elf_rejects_invalid_container(tmp_path, text):
    path = tmp_path / "bad.elf"
    path.write_bytes(text)
    with pytest.raises(SdkError):
        linked_segments(path)


def test_sdk_explicit_alu_form_is_not_a_machine_word_escape():
    assert normalize("IF NE AR = 0x0002 + 1", "sdk") == "if ne ar = inc_const(0x0002);"
    assert normalize("AR = 0x0100 - AX0", "sdk") == "ar = -ax0 + 0x0100;"
    assert normalize("IF NE AR = 0x0002 + 1") == "if ne ar = pass (0x0002 + 1);"


def test_real_word_width_endian_relocation_and_reproducibility(tmp_path, sdk):
    source = Path(__file__).resolve().parents[2] / "tools/sunplus_sdk/examples/core.dsp"
    a = build_image((source,), tmp_path / "a", sdk, MemoryLayout(pm_start=0x1800, dm_start=0x100))
    b = build_image((source,), tmp_path / "b", sdk, MemoryLayout(pm_start=0x1800, dm_start=0x100))
    pm, dm = a.segments
    assert (pm.space, pm.word_address, pm.word_bytes, pm.word_count) == ("PM", 0x1800, 3, 11)
    assert pm.data.hex() == "22180f3c003515803e22621f22205123301f0610000710000c00c00c00800a000f"
    assert (dm.space, dm.word_address, dm.word_bytes, dm.word_count) == ("DM", 0x100, 2, 2)
    assert dm.data == bytes.fromhex("1234abcd")
    assert a.segments == b.segments and a.elf_path.read_bytes() == b.elf_path.read_bytes()
    metadata = json.loads(a.manifest_path.read_text())
    assert metadata["state"] == "ASSEMBLED_AND_LINKED_NOT_HARDWARE_ACCEPTED"


def test_two_module_call_is_linked_to_requested_base(tmp_path, sdk):
    first = source_at(tmp_path, ".section/pm program0;\n.extern worker;\ncall worker;\nrts;\n", "caller.dsp")
    second = source_at(tmp_path, ".section/pm program0;\n.global worker;\nworker: ar=ar+1;\nrts;\n", "worker.dsp")
    result = build_image((first, second), tmp_path / "out", sdk, MemoryLayout(pm_start=0x200))
    assert result.segments[0].data == bytes.fromhex("1c202f0a000f22621f0a000f")


def test_missing_symbol_fails_without_success_manifest(tmp_path, sdk):
    src = source_at(tmp_path, ".section/pm program0;\n.extern absent;\ncall absent;\n")
    with pytest.raises(SdkError, match="ld21 exited"):
        build_image((src,), tmp_path / "out", sdk)
    assert not (tmp_path / "out/image.json").exists()


def test_invalid_operand_and_overflow_are_rejected(tmp_path, sdk):
    bad = source_at(tmp_path, ".section/pm program0;\nar=inc_const(0x1234);\n")
    with pytest.raises(SdkError, match="as218x exited"):
        build_image((bad,), tmp_path / "bad", sdk)
    large = source_at(tmp_path, ".section/pm program0;\nnop;\nrts;\n", "large.dsp")
    with pytest.raises(SdkError):
        build_image((large,), tmp_path / "overflow", sdk, MemoryLayout(pm_end=0))


def test_output_overwrite_is_rejected(tmp_path, sdk):
    src = source_at(tmp_path, ".section/pm program0;\nrts;\n")
    out = tmp_path / "keep"
    out.mkdir()
    (out / "marker").write_text("preserved")
    with pytest.raises(SdkError, match="overwrite"):
        build_image((src,), out, sdk)
    assert (out / "marker").read_text() == "preserved"


def test_cli_handles_spaces_without_shell_interpretation(tmp_path, sdk):
    src = source_at(tmp_path, ".section/pm program0;\nrts;\n", "path with spaces.dsp")
    out = tmp_path / "output with spaces"
    run = subprocess.run([sys.executable, "-m", "tools.sunplus_sdk", "--sdk-root", str(sdk.root),
                          "build", str(src), "--output", str(out)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert (out / "pm.bin").read_bytes() == bytes.fromhex("0a000f")


def test_sdk_elf_reader_rejects_objects_and_corrupt_directory(tmp_path, sdk):
    src = source_at(tmp_path, ".section/pm program0;\nrts;\n")
    result = build_image((src,), tmp_path / "out", sdk)
    with pytest.raises(SdkError, match="ET_EXEC"):
        linked_segments(tmp_path / "out/source-000.o")
    raw = bytearray(result.elf_path.read_bytes())
    endian = "<" if raw[5] == 1 else ">"
    struct.pack_into(endian + "I", raw, 32, len(raw) + 1024)
    bad = tmp_path / "bad-directory.elf"
    bad.write_bytes(raw)
    with pytest.raises(SdkError, match="directory"):
        linked_segments(bad)


def test_unmapped_source_section_does_not_silently_disappear(tmp_path, sdk):
    src = source_at(tmp_path, ".section/pm program0;\nrts;\n.section/pm forgotten;\nnop;\n")
    with pytest.raises(SdkError):
        build_image((src,), tmp_path / "out", sdk)


def test_explicit_entry_metadata_preserves_segments(tmp_path, sdk):
    src = source_at(tmp_path, ".section/pm program0;\nrts;\n")
    result = build_image((src,), tmp_path / "out", sdk, MemoryLayout(pm_start=0x1800), entry_word=0x1800)
    data = result.elf_path.read_bytes()
    assert struct.unpack_from("<I" if data[5] == 1 else ">I", data, 24)[0] == 0x1800
    assert result.segments[0].data == bytes.fromhex("0a000f")
    with pytest.raises(SdkError):
        build_image((src,), tmp_path / "bad", sdk, MemoryLayout(pm_start=0x1800), entry_word=0x17ff)


def test_parallel_discard_adapts_to_vendor_none_form():
    assert normalize("AR = AF - AX0 ,AR = AR", "sdk") == "none = af - ax0;"
    assert normalize("AR = MR1 OR AF ,AR = AR", "sdk") == "none = mr1 or af;"
