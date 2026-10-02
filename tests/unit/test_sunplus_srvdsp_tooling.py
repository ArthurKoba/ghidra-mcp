from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SLASPEC = ROOT / "processors" / "SunplusSPHEAudioDSP" / "data" / "languages" / "sunplus_sphe_audio_dsp.slaspec"
SERVICE = ROOT / "src" / "main" / "java" / "com" / "xebyte" / "core" / "ProgramScriptService.java"
POST = ROOT / "src" / "main" / "java" / "com" / "xebyte" / "core" / "SunplusSrvdspPostProcessor.java"
ANALYZE = ROOT / "ghidra_scripts" / "SunplusSrvdspAnalyze.java"
ACCEPT = ROOT / "ghidra_scripts" / "SunplusSrvdspAcceptance.java"
SMOKE = ROOT / "ghidra_scripts" / "SunplusDSPDecodeSmoke.java"


def test_sleigh_declares_big_endian_24bit_token_and_srvdsp_families() -> None:
    text = SLASPEC.read_text()
    assert "define token inst24(24) endian = big" in text
    assert "define alignment=3;" in text
    assert "define space PM" in text and "wordsize=3" in text
    assert "define space DM" in text and "wordsize=2" in text
    assert "define space IO" in text and "wordsize=2" in text

    required_markers = [
        ":DMREAD RegSel, addr14",
        ":DMWRITE addr14, RegSel",
        ":DMWRITE DagI, DagM, DReg4",
        ':AR "=" ALUX "-" ALUY',
        ':MR "=" MACX "*" MACY',
        ':AR "=" ALUX "- 1"',
        ':"IF EQ JUMP" JumpAddr',
        ':"IF NE JUMP" JumpAddr',
        ':"IF GT JUMP" JumpAddr',
        ':"IF LT JUMP" JumpAddr',
        ':"DO" LoopAddr "UNTIL CE"',
        ':SR "=" "ASHIFT" ShiftX "BY 4"',
        ':SR "=" "LSHIFT" ShiftX "BY -10 (HI)"',
        ':AY0 "=" "SR0"',
        ':AR "=" "SR1"',
        ':"IF NE RTS"',
        ":RTI",
        ':IOWRITE ioaddr, IODReg',
    ]
    for marker in required_markers:
        assert marker in text, marker


def test_srvdsp_preanalysis_hook_is_integrated_in_all_analysis_entry_paths() -> None:
    service = SERVICE.read_text()
    assert "private boolean prepareAndRunAutoAnalysis" in service
    assert "SunplusSrvdspPostProcessor.prepare" in service
    # headless open, already-open GUI/cache, fresh GUI open, import_file, reanalyze
    assert service.count("prepareAndRunAutoAnalysis(") >= 6  # declaration + five call sites

    post = POST.read_text()
    assert 'LANGUAGE_ID = "SunplusSPHEAudioDSP:BE:16:default"' in post
    assert "PM_BASE = 0x1800L" in post
    assert "getAddressableUnitSize()" in post
    assert "CODE_FIRST = 0x1820L" in post
    assert "CODE_LAST = 0x1894L" in post
    assert "EXPECTED_LOCAL_HANDLERS = 9" in post
    assert "program.setImageBase(desiredBase, true)" in post
    assert "new DisassembleCommand" in post
    assert "new CreateFunctionCmd" in post
    assert "countMissingInstructions" in post


def test_analysis_and_decompiler_acceptance_scripts_are_present() -> None:
    analyze = ANALYZE.read_text()
    accept = ACCEPT.read_text()
    assert "EXPECTED_BASE = 0x1800L" in analyze
    assert "targets.size() != 9" in analyze
    assert "missing_code_words" in analyze
    assert "DecompInterface" in accept
    assert "decompileCompleted()" in accept
    assert "getHighFunction()" in accept
    assert "getC().isBlank()" in accept
    assert "SUNPLUS_SRVDSP_ACCEPTANCE=PASS" in accept


def test_decode_smoke_normalizes_word_addressed_flow_targets() -> None:
    smoke = SMOKE.read_text()
    assert "getAddressableUnitSize()" in smoke
    assert "targetWordAddress" in smoke
    assert "wordAddress * pm.getAddressableUnitSize()" in smoke


def test_srvdsp_ce_loop_is_modeled_as_real_control_flow() -> None:
    text = SLASPEC.read_text()
    accept = ACCEPT.read_text()
    assert "define context DSPCTX" in text
    assert "srvdsp_ce_loop_end=(0,0) noflow" in text
    assert "globalset(LoopAddr, srvdsp_ce_loop_end)" in text
    assert "CNTR = CNTR - 1" in text
    assert "if (CNTR != 0) goto inst_start" in text
    assert "srvdsp_wrapper_mode=(1,1) noflow" in text
    assert "srvdsp_wrapper_mode=1" in text
    assert "dsp_do_until" not in text
    assert "PcodeOp.INT_SUB" in accept
    assert "PcodeOp.CBRANCH" in accept
    assert 'contains("dsp_do_until")' in accept


def test_srvdsp_analysis_scaffold_materializes_dm_and_void_actions() -> None:
    post = POST.read_text()
    analyze = ANALYZE.read_text()
    accept = ACCEPT.read_text()
    for text in (post, analyze):
        assert "SRVDSP_DM_STATE" in text
        assert "DM_STATE_SIZE_BYTES" in text
        assert "createUninitializedBlock" in text
        assert "VoidDataType.dataType" in text
        assert "getSignatureSource() != SourceType.USER_DEFINED" in text
    assert "findCanonicalPmImageBlock" in post
    assert "memory.getSize() != EXPECTED_SIZE_BYTES" not in post
    assert '"SRVDSP_DM_STATE".equals(dmState.getName())' in accept
    assert '!"void".equals(function.getReturnType().getName())' in accept


def test_srvdsp_processor_model_revision_refresh_is_bounded() -> None:
    post = POST.read_text()
    analyze = ANALYZE.read_text()
    accept = ACCEPT.read_text()
    for text in (post, analyze):
        assert "ANALYSIS_MODEL_VERSION = 3" in text
        assert 'MODEL_VERSION_OPTION = "srvdsp.analysis_model_version"' in text
        assert "MODEL_REFRESH_WORDS" in text
        assert "WRAPPER_CONTEXT_REGISTER" in text
        assert "clearCodeUnits(start, end, false)" in text
        assert "options.setInt(MODEL_VERSION_OPTION, ANALYSIS_MODEL_VERSION)" in text
    assert 'getOptions("Sunplus SPHE Audio DSP")' in accept
    assert 'getInt("srvdsp.analysis_model_version", 0)' in accept
    assert 'getRegister("srvdsp_wrapper_mode")' in accept
    assert 'startsWith("JUMP_RESIDENT")' in accept


def test_decode_smoke_covers_codec_profile_extension_words() -> None:
    smoke = SMOKE.read_text()
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    for word, expected in (
        ("0x0A001F", "RTI"),
        ("0x180250", "IF EQ JUMP"),
        ("0x22E21F", "AR = AR - 1"),
        ("0x0F02F6", "LSHIFT AR BY -10 (HI)"),
        ("0x0D00AF", "AR = SR1"),
        ("0x18036F", "JUMP $0036"),
    ):
        assert word in smoke
        assert expected in smoke
    assert "19820f0a000f80023a80021a0a001f18025022e21f0f02f60d00af18036f" in workflow
    assert "bytes.fromhex" in workflow
