from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SLASPEC = ROOT / "processors" / "SunplusSPHEAudioDSP" / "data" / "languages" / "sunplus_sphe_audio_dsp.slaspec"
SERVICE = ROOT / "src" / "main" / "java" / "com" / "xebyte" / "core" / "ProgramScriptService.java"
POST = ROOT / "src" / "main" / "java" / "com" / "xebyte" / "core" / "SunplusSrvdspPostProcessor.java"
ANALYZE = ROOT / "ghidra_scripts" / "SunplusSrvdspAnalyze.java"
ACCEPT = ROOT / "ghidra_scripts" / "SunplusSrvdspAcceptance.java"
SMOKE = ROOT / "ghidra_scripts" / "SunplusDSPDecodeSmoke.java"
CORPUS_SCAN = ROOT / "ghidra_scripts" / "SunplusCodecCorpusGapScan.java"
REACH_SCAN = ROOT / "ghidra_scripts" / "SunplusCodecReachableScan.java"


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
        ':SR "=" "ASHIFT" ShiftX "BY" sexp8 "(HI)"',
        ':SR "=" "ASHIFT" ShiftX "BY" sexp8 "(LO)"',
        ':SR "=" "LSHIFT" ShiftX "BY" sexp8 "(HI)"',
        ':SR "=" "LSHIFT" ShiftX "BY" sexp8 "(LO)"',
        ':"" IntDst "=" IntSrc',
        ':"IF NE RTS"',
        ':AF "=" ALUX "-" ALUY',
        ':ENA_INTS',
        ':"IF EQ RTS"',
        ':"IF GE RTS"',
        ':"IF LT" "AR" "=" ALUX "+" ALUY',
        ':"IF GE JUMP" JumpAddr',
        ':"IF EQ CALL" JumpAddr',
        ':SR "=" "ASHIFT" ShiftX "BY" sexp8 "(HI)"',
        ':SR "=" "ASHIFT" ShiftX "BY" sexp8 "(LO)"',
        ':SAT_MR is whole24=0x050000',
        ':IDLE is whole24=0x028000',
        ':NONE "=" ALUX "-" ALUY',
        ':NONE "=" ALUX "+" ALUY',
        ':AR "=" ALUX "+" ALUY "," DReg4 "=" DReg',
        ':AF "=" ALUX "-" ALUY "," DReg4 "=" DReg',
        ':"" DReg4 "=" "PM(" DagI "," DagM ")"',
        ':"PM(" DagI "," DagM ")" "=" DReg4',
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


def test_codec_ce_loop_has_real_generic_pcode_and_native_fixture() -> None:
    text = SLASPEC.read_text()
    assert "codec_ce_loop_end=(2,2) noflow" in text
    assert "globalset(LoopAddr, codec_ce_loop_end)" in text
    assert "build instruction;" in text
    assert "if (CNTR == 0) goto <codec_ce_done>;" in text
    assert "goto [DSP_LOOP_START];" in text
    assert "local start:2 = inst_next / 3;" in text
    assert "dsp_do_until_ce(LoopAddr);" not in text
    fixture = ROOT / "tests/fixtures/sunplus_sphe_audio_dsp/pcm_ce_loop_12b8.bin"
    assert fixture.read_bytes().hex() == "3c0205152bde6000a11222a512a2f96800fd0a000f"
    regression = ROOT / "ghidra_scripts/SunplusDSPCeLoopRegression.java"
    assert "SUNPLUS_CODEC_CE_LOOP_ACCEPTANCE=PASS" in regression.read_text()


def test_codec_nested_ce_count_and_loop_stack_regressions() -> None:
    text = SLASPEC.read_text()
    assert "codec_ce_nested_mode=(4,4) noflow" in text
    assert "codec_ce_nested_mode=0 & type11=5" in text
    assert "codec_ce_nested_mode=1 & type11=5" in text
    assert "codec_ce_nested_mode=1 & op4=3" in text
    assert "codec_ce_nested_mode=1 & type3=4" in text
    assert "DSP_LOOP_DEPTH" in text and "DSP_COUNT_DEPTH" in text
    assert "codec_cntr_load(newvalue)" in text
    assert "DSP_COUNT0 = CNTR" in text
    assert "DSP_LOOP_START_SHADOW3 = DSP_LOOP_START" in text
    assert "DSP_LOOP_START = DSP_LOOP_START_SHADOW3" in text
    assert "CNTR = DSP_COUNT0" in text and "CNTR = DSP_COUNT3" in text
    assert ':LDI CNTR, data14 is srvdsp_wrapper_mode=0' in text
    assert ':DMREAD CNTR, addr14 is srvdsp_wrapper_mode=0' in text
    fixture_dir = ROOT / "tests/fixtures/sunplus_sphe_audio_dsp"
    assert (fixture_dir / "nested_ce_2x3.bin").stat().st_size == 30
    assert (fixture_dir / "nested_ce_4deep.bin").stat().st_size == 57
    direct = (fixture_dir / "nested_ce_dmread_2x3.bin").read_bytes()
    assert len(direct) == 30 and direct[6:9] == bytes.fromhex("8c7805")
    acceptance = (ROOT / "ghidra_scripts/SunplusNestedCeLoopAcceptance.java").read_text()
    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "nestedWords" in acceptance
    assert "Nested mode escaped proved instruction set" in acceptance
    assert "NESTED_CE_RUNTIME_ACCEPTANCE=PASS" in acceptance
    assert 'emulator.writeMemoryValue(counterAddress, 2, 3)' in acceptance
    assert acceptance.count("emulator.setContextRegister(nestedMode, BigInteger.ONE);") == 2
    assert "Verify Sunplus bounded nested CE loops" in workflow


def test_codec_nested_ce_native_interprocedural_calls() -> None:
    text = SLASPEC.read_text()
    assert "DSP_CALL_DEPTH" in text and "DSP_CALL_RET0" in text
    assert "DSP_CALL_RET3" in text
    assert "codec_call_push(nextword)" in text
    assert "codec_call_return()" in text
    assert "codec_ce_nested_mode=1 & type10=3 & call18=1" in text
    for form in ("IF EQ CALL", "IF NE CALL", "IF GT CALL", "IF LT CALL"):
        assert f':"{form}" JumpAddr is codec_ce_nested_mode=1' in text
    for form in ("IF EQ RTS", "IF NE RTS", "IF GT RTS", "IF GE RTS", "IF LT RTS"):
        assert f':"{form}" is codec_ce_nested_mode=1' in text
    root = ROOT / "tests/fixtures/sunplus_sphe_audio_dsp"
    assert (root / "nested_ce_call_2x3.bin").stat().st_size == 39
    assert (root / "nested_ce_call_2stage.bin").stat().st_size == 51
    conditional = (root / "nested_ce_condcall_2x3.bin").read_bytes()
    assert len(conditional) == 39 and conditional[6:9] == bytes.fromhex("1c3091")
    caller = (ROOT / "ghidra_scripts/SunplusNestedCallCeAcceptance.java").read_text()
    gated = (ROOT / "ghidra_scripts/SunplusConditionalCeCallAcceptance.java").read_text()
    assert "CROSS_CALL_CE_PCODE_RETURN_ACCEPTANCE=PASS" in caller
    assert "CONDITIONAL_CE_CALL_ACCEPTANCE=PASS" in gated
    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "Verify Sunplus nested CE calls and returns" in workflow


def test_signed_immediate_shifts_use_static_sign_and_no_dead_pcode_edges() -> None:
    text = SLASPEC.read_text()
    assert "sexp_sign = (7,7)" in text
    for mnemonic, mode, selector in (
        ("ASHIFT", "HI", 4),
        ("ASHIFT", "LO", 6),
        ("LSHIFT", "HI", 0),
        ("LSHIFT", "LO", 2),
    ):
        for sign in (0, 1):
            needle = (f':SR "=" "{mnemonic}" ShiftX "BY" sexp8 "({mode})" '
                      f'is type15=0x1e & sf4={selector} & sexp_sign={sign}')
            assert needle in text
    fixture = ROOT / "tests/fixtures/sunplus_sphe_audio_dsp/immediate_signed_shift.bin"
    assert fixture.read_bytes().hex() == "41480e0f160841480e0f16f80a000f0f26080f26f80f36080f36f80f06080f06f8"
    script = (ROOT / "ghidra_scripts/SunplusSignedImmediateShiftAcceptance.java").read_text()
    assert "SUNPLUS_SIGNED_IMMEDIATE_SHIFT_ACCEPTANCE=PASS" in script
    assert "SIGNED_SHIFT_C completed=" in script
    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "Verify Sunplus signed immediate shifter and C" in workflow


def test_signed_immediate_or_shifts_eliminate_constant_dead_branches() -> None:
    text = SLASPEC.read_text()
    for direction, sf in (("HI", 1), ("LO", 3)):
        for sign in (0, 1):
            needle = (f':SR "=" "SR OR LSHIFT" ShiftX "BY" sexp8 "({direction})" '
                      f'is type15=0x1e & sf4={sf} & sexp_sign={sign}')
            assert needle in text
    assert "t15ohi_r" not in text and "t15olo_r" not in text
    fixture = ROOT / "tests/fixtures/sunplus_sphe_audio_dsp/immediate_or_shift.bin"
    assert fixture.read_bytes().hex() == "0f0a080f0af80f1a0c0f1afc0a000f"
    acceptance = (ROOT / "ghidra_scripts/SunplusOrImmediateShiftAcceptance.java").read_text()
    assert "SUNPLUS_OR_SHIFT_ACCEPTANCE=PASS" in acceptance
    assert "SUNPLUS_OR_SHIFT_C completed=" in acceptance
    assert "Verify Sunplus OR immediate shifts and C output" in (
        ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")


def test_se_proven_negative_type12_context_and_arithmetic_gate() -> None:
    text = SLASPEC.read_text()
    assert "codec_se_proven_negative=(7,7) noflow" in text
    for mode in ("shift_d=1 & sf4=4", "shift_d=0 & sf4=4",
                 "shift_d=0 & sf4=6"):
        assert f"codec_se_proven_negative=1 & type12=9 & {mode}" in text
    assert text.count("local magnitude:2 = -SE;") >= 3
    assert text.count("local res:4 = src s>> magnitude;") >= 3
    native = ROOT / "tests/fixtures/sunplus_sphe_audio_dsp/se_negative_type12.bin"
    assert native.read_bytes().hex() == "1236631222a512a2f9"
    script = (ROOT / "ghidra_scripts/SunplusSeNegativeArithmeticAcceptance.java").read_text()
    assert "SE_NEGATIVE_ARITHMETIC_ACCEPTANCE=PASS" in script
    c_probe = (ROOT / "ghidra_scripts/SunplusSeNegativeKnownCProbe.java").read_text()
    assert "SE_NEGATIVE_STATIC_C_ACCEPTANCE=PASS" in c_probe
    assert "ROLLED_BACK" in c_probe
    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "Verify Sunplus proven-negative SE Type-12 shifts" in workflow


def test_srvdsp_ce_loop_is_modeled_as_real_control_flow() -> None:
    text = SLASPEC.read_text()
    accept = ACCEPT.read_text()
    assert "define context DSPCTX" in text
    assert "srvdsp_ce_loop_end=(0,0) noflow" in text
    assert "globalset(LoopAddr, srvdsp_ce_loop_end)" in text
    assert "CNTR = CNTR - 1" in text
    assert "if (CNTR != 0) goto inst_start" in text
    assert "ASF" in text
    assert ':"IF NEG JUMP" JumpAddr' in text
    assert "if (ASF != 0) goto JumpAddr" in text
    assert ':"IF POS JUMP" JumpAddr' in text
    assert "if (ASF == 0) goto JumpAddr" in text
    assert "srvdsp_wrapper_mode=(1,1) noflow" in text
    assert "srvdsp_wrapper_mode=1" in text
    assert "define pcodeop dsp_do_until_ce" in text
    assert 'srvdsp_wrapper_mode=0 & codec_ce_nested_mode=0 & type11=5' in text
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
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
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


def test_codec_profile_extension_covers_observed_misc_and_multifunction_forms() -> None:
    text = SLASPEC.read_text()
    for marker in (
        ':"IF LT RTS"',
        ':"IF GT RTS"',
        ':DIS_G_MODE is whole24=0x0c0080',
        ':DIS_TIMER is whole24=0x0c8000',
        ':DIS_M_MODE is whole24=0x0c2000',
        ':ENA_AR_SAT is whole24=0x0c0c00',
        ':DIS_AR_SAT is whole24=0x0c0800',
        ':ENA_M_MODE is whole24=0x0c3000',
        ':ENA_TIMER is whole24=0x0cc000',
        ':"MODIFY(" ModI "," ModM ")"',
        ':"POP STS, POP CNTR, POP PC, POP LOOP" is whole24=0x04001f',
        ':SR "=" "LSHIFT" ShiftX "(LO)," DReg4 "=" DReg',
        ':SR "=" "LSHIFT" ShiftX "(LO)"',
        ':SR "=" "SR OR LSHIFT" ShiftX "(LO)"',
        ':AR "=" ALUX "+" ALUY "," DReg4 "=" "DM(" DagI "," DagM ")"',
        ':AR "=" ALUY "- 1," DReg4 "=" "DM(" DagI "," DagM ")"',
        ':"MR = MR + MX0 * 0 (SS)"',
    ):
        assert marker in text, marker
    # Type-8 NONE encodings update status without fabricating an AR/AF write.
    assert ':NONE "=" ALUX "+" ALUY' in text
    assert ':NONE "=" ALUX "-" ALUY' in text


def test_codec_corpus_gap_scanner_is_bounded_and_reports_explicit_gaps() -> None:
    text = CORPUS_SCAN.read_text()
    assert 'requested > 0x4000L' in text
    assert 'monitor.isCancelled()' in text
    assert 'memory.contains(address)' in text
    assert 'memory.contains(address.add(2))' in text
    assert 'memory.getBytes(address, raw)' in text
    assert 'trailing_bytes=' in text
    assert 'SUNPLUS_CORPUS_SCAN' in text
    assert 'println("GAP "' in text


def test_codec_reachable_scanner_follows_native_flow_and_reports_gaps() -> None:
    text = REACH_SCAN.read_text()
    assert 'requested > 0x4000L' not in text
    assert 'maxWords > 0x4000L' in text
    assert 'monitor.isCancelled()' in text
    assert 'ins.getFallThrough()' in text
    assert 'ins.getFlows()' in text
    assert 'SUNPLUS_REACHABLE_SCAN' in text
    assert 'println("GAP "' in text



def test_pm24_dynamic_accesses_use_lossless_width_callother_interfaces() -> None:
    """Avoid direct 3-byte PM LOAD/STORE in the full C optimizer.

    These CALL_OTHER interfaces preserve word addresses and 24-bit values in
    generated C, but require an executor-side PM userop library for emulation.
    """
    text = SLASPEC.read_text()
    assert "define space PM" in text and "wordsize=3" in text
    assert "define pcodeop dsp_pm_load24;" in text
    assert "define pcodeop dsp_pm_store24;" in text
    assert "local word:3 = dsp_pm_load24(a);" in text
    assert "DReg4 = word[8,16];" in text
    assert "PX = zext(word[0,8]);" in text
    assert "local hi:3 = zext(DReg4) << 8;" in text
    assert "local lo:3 = zext(PX) & 0xff;" in text
    assert "dsp_pm_store24(a,word);" in text
    assert "an emulator that executes these userops must provide a backing" in text

    acceptance = (ROOT / "ghidra_scripts" /
        "SunplusCodecFullCAcceptance.java").read_text()
    for module, count in (
        ("srvdsp.bin", 9),
        ("aux-profile.bin", 61),
        ("pcm-profile.bin", 4),
        ("ac3-profile.bin", 25),
        ("dts-profile.bin", 98),
    ):
        assert f'"{module}", {count}' in acceptance
    assert "SUNPLUS_CODEC_FULL_C_ACCEPTANCE=PASS" in acceptance
    assert "decompileCompleted()" in acceptance
    assert "currentProgram.getFunctionManager().getFunctionCount()" in acceptance


def test_codec_sequential_ce_with_static_direct_backedges() -> None:
    text = SLASPEC.read_text()
    assert "codec_ce_direct_backedge=(8,8) noflow" in text
    assert "codec_ce_direct_start=(9,24) noflow" in text
    assert "codecDirectLoopStart:" in text
    assert "goto codecDirectLoopStart;" in text
    assert "codec_ce_direct_backedge=0 & codec_ce_nested_mode=0" in text
    fixture = ROOT / "tests/fixtures/sunplus_sphe_audio_dsp/pcm_sequential_ce_07a4.bin"
    content = fixture.read_bytes()
    assert len(content) == 54
    assert content[6:9].hex() == "147a7e"
    assert content[27:30].hex() == "147b2e"
    assert content[-3:].hex() == "0a000f"
    script = (ROOT / "ghidra_scripts/SunplusPcmSequentialCeLoopAcceptance.java").read_text()
    assert "SUNPLUS_SEQUENTIAL_CE_ACCEPTANCE=PASS" in script
    assert 'new String[][]{{"07a7","07a7"},{"07b2","07ae"}}' in script
    workflow = (ROOT / ".github/workflows/tests.yml").read_text()
    assert "Verify Sunplus sequential CE loops across resident call" in workflow
    assert "SunplusPcmSequentialCeLoopAcceptance.java" in workflow
