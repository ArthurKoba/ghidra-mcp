"""Verify the production image contains native Sunplus C-generator repairs.

Ghidra's SLEIGH language alone cannot recover the accepted PCM jump-table
range or preserve correct decompiler C output; native fixes must be built too.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / 'docker/Dockerfile').read_text()
PATCHES = ROOT / 'patches/ghidra-12.1.3'


def test_release_builds_native_decompiler_from_pinned_source():
    assert 'ARG GHIDRA_VERSION=12.1.3' in DOCKERFILE
    assert 'test "${GHIDRA_VERSION}" = "12.1.3"' in DOCKERFILE
    assert 'COPY patches/ghidra-12.1.3 /tmp/ghidra-native-patches' in DOCKERFILE
    assert 'make -C "${CPP}" ghidra_opt -j2' in DOCKERFILE
    assert 'install -m 0755 "${CPP}/ghidra_opt"' in DOCKERFILE
    assert 'Ghidra/Features/Decompiler/os/linux_x86_64/decompile' in DOCKERFILE
    assert DOCKERFILE.index('make -C "${CPP}" ghidra_opt') < DOCKERFILE.index('# Stage 2: Runtime')


def test_release_applies_all_native_repairs_without_replacing_code_with_gaps():
    filenames = (
        'native-word-addressed-ptradd-guard.patch',
        'native-unresolved-branchind-c.patch',
        'native-explicit-selfloop-c.patch',
    )
    for name in filenames:
        path = PATCHES / name
        assert path.exists() and path.stat().st_size > 200
        assert DOCKERFILE.count(name) == 1
    unbounded = (PATCHES / filenames[1]).read_text()
    assert 'CPUI_BRANCHIND' in unbounded
    assert 'PcodeOp::noreturn' in unbounded
    assert 'CPUI_INT_RIGHT' in unbounded
    assert 'maxValue' in unbounded
    assert '__ghidra_unresolved_indirect_jump' in unbounded
    assert 'fail_dynamic' not in unbounded
    assert 'Do nothing block with infinite loop' in (PATCHES / filenames[2]).read_text()
    assert 'getWordSize()' in (PATCHES / filenames[0]).read_text()


def test_image_copies_processor_and_compiles_sleigh():
    assert 'COPY processors/SunplusSPHEAudioDSP ' in DOCKERFILE
    assert '/opt/ghidra/support/sleigh' in DOCKERFILE
    language = ROOT / 'processors/SunplusSPHEAudioDSP/data/languages'
    source = (language / 'sunplus_sphe_audio_dsp.slaspec').read_text()
    assert '@include "sunplus_stack_runtime.sinc"' in source
    assert '@include "sunplus_stack_instructions.sinc"' in source
    assert 'codec_arch_stack_mode=(28,28) noflow' in source
    assert 'codec_arch_stack_mode=0' in source
    assert 'codec_arch_stack_mode=1' in source


def test_release_manifest_pins_the_complete_source_bundle():
    import hashlib
    import json
    manifest = json.loads((ROOT / "processors/SunplusSPHEAudioDSP/MODEL_RELEASE.json").read_text())
    assert manifest["status"] == "LOCAL_ACCEPTED_CANONICAL_ANALYZER_PENDING"
    assert manifest["Ghidra"] == "12.1.3"
    assert manifest["compiled_sla_sha256"] == "b8bc249a835066645ee8244c3572578009418e35ae5977e9e4b77a35f12e22a9"
    assert len(manifest["files_sha256"]) == 9
    for name, digest in manifest["files_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    assert manifest["reproducible_local"]["native_C"] == 462
    assert manifest["reproducible_local"]["CE_indirect_proven"] == 58
    latest = manifest["latest_local_source_native_20261026"]
    assert latest["source_native_function_C_generated"] == 547
    assert latest["source_native_DO_CE_count"] == 548
    assert latest["vector_handler_paths_RTI_complete"] == 4
    assert latest["C_warning_lines"] == 0
    assert latest["canonical_save_readback"] == "PENDING"
