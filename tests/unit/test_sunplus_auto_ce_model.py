"""Safety and integration contracts for the single general Sunplus Ghidra analyzer."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "src/main/java/com/xebyte/sunplus/SunplusNativeCeAutoAnalyzer.java"
BROAD = ROOT / "ghidra_scripts/SunplusDSPAutoCeBroadDryRun.java"


def test_architecture_registration_and_no_profile_specific_recovery():
    text = MODEL.read_text()
    assert 'extends AbstractAnalyzer' in text
    assert 'AnalyzerType.FUNCTION_ANALYZER' in text
    assert 'LANGUAGE.equals(program.getLanguageID()' in text
    assert 'setDefaultEnablement(false)' in text  # hold until independent fresh-import gate
    assert 'srvdsp_wrapper_mode' in text  # reserved hardware contract
    assert 'PM:2513' not in text and 'PM:1e70' not in text
    assert 'profile.bin' not in text and 'ac3-profile' not in text


def test_one_generic_bounded_hardware_flow_pass_and_fail_closed_c_gate():
    text = MODEL.read_text()
    assert 'MAX_BACKWARD_WRITER = 16' in text
    assert 'MAX_LOOP_WORDS = 1024' in text
    assert 'returnsViaSharedPcStackAt(' in text
    assert 'nativeCounterWrite(' in text
    assert 'intersects(l, other)' in text
    assert 'code(last, PcodeOp.CBRANCH) < 1' in text
    assert 'code(last, PcodeOp.BRANCHIND) != 1' in text
    assert 'alreadyDirect.signum() != 0' in text
    assert 'sourceLoopCountFlowBalanced(l,p,monitor)' in text
    assert 'cLoops(after) < cLoops(before)' in text
    assert 'cWarnings(after) > cWarnings(before)' in text
    assert 'cLoops(after) < cLoops(before)' in text
    assert 'program.endTransaction(tx, accept && commitChanges)' in text


def test_dry_run_never_opens_transaction_even_from_mcp_script():
    text = MODEL.read_text()
    assert text.index('if (!commitChanges) {') < text.index('program.startTransaction(')
    assert 'return run(program, set, monitor, log, false)' in text
    broad = BROAD.read_text()
    assert 'dryRun(currentProgram,loaded,monitor,evidence)' in broad
    assert 'program.startTransaction' not in broad


def test_resident_fresh_import_uses_native_default_abi_not_unknown():
    source = (ROOT / "src/main/java/com/xebyte/core/SunplusSrvdspPostProcessor.java").read_text()
    assert '"unknown".equals(function.getCallingConventionName())' in source
    assert 'program.getCompilerSpec().getDefaultCallingConvention().getName()' in source
    assert 'function.setCallingConvention(defaultConvention);' in source
    assert 'function.getSignatureSource() != SourceType.USER_DEFINED' in source
    assert source.index('function.setCallingConvention(defaultConvention);') < source.index('function.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);')


def test_post_analyze_ce_runs_after_ghidra_transaction_and_save():
    bridge = (ROOT / "src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert 'runAutoAnalysisAndPersistFlags(program, force)' in bridge
    assert 'nativeCe.applyAfterSavedAnalysis(program,' in bridge
    assert bridge.index('if (!runAutoAnalysisAndPersistFlags(program, force))') < bridge.index('nativeCe.applyAfterSavedAnalysis(program,')
    assert 'persistProgram(program, "Sunplus DSP automatic source-native DO/CE complete")' in bridge
    analyzer = MODEL.read_text()
    assert 'if (program.isChanged()) {' in analyzer
    assert 'return run(program, loaded, monitor, log, true);' in analyzer


def test_forced_ce_rollback_requires_qa_folder_and_worker_opt_in():
    source = MODEL.read_text()
    assert 'RUSH28-architecture-import-validation/' in source
    assert 'RUSH28_NATIVE_CE_ABORT_AFTER_FIRST_QA' in source
    assert 'QA_FAULT_INJECTED_AFTER_NATIVE_CE_RECODE' in source
    assert source.index('QA_FAULT_INJECTED_AFTER_NATIVE_CE_RECODE') < source.index('DecompInterface verify = new DecompInterface()')
    assert 'return false;' in source[source.index('Native CE recovery rejected'):]


def test_codec_reset_native_pm_word_vs_byte_address_mapping():
    path = ROOT / "src/main/java/com/xebyte/sunplus/SunplusDspResetVectorBootstrap.java"
    source=path.read_text()
    assert 'pm.getAddress((long) word * pm.getAddressableUnitSize())' in source
    assert 'Source PM24 reset vector flow proof failed' in source
    assert 'function.setCallingConvention' not in source
    assert 'fn.setCallingConvention(' in source
    assert 'program.getCompilerSpec().getDefaultCallingConvention().getName()' in source


def test_automatic_sparse_dm16_c_quality_gate_precedes_ce_flow():
    source=(ROOT / "src/main/java/com/xebyte/sunplus/SunplusNativeDmWordAutoNormalizer.java").read_text()
    assert 'sourceProvesDm16(p,monitor)' in source
    assert 'Stats baseline=stats(before)' in source
    assert 'result.overlaps()>=baseline.overlaps()' in source
    assert 'Undefined2DataType.dataType' in source
    assert 'op.getInput(0).getOffset() != dmSpaceId' in source
    assert 'op.getInput(1).isConstant()' in source
    assert 'originalWord < 0 || originalWord > 0xffff' in source
    assert 'owner.getValue().contains(WARNING)' in source
    assert 'original initialized' not in source or 'Initialized' not in source
    assert 'hardware' in source.lower() and 'UNKNOWN' in source
    bridge=(ROOT / "src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert bridge.index('SunplusNativeDmWordAutoNormalizer.applyAfterSavedAnalysis(') < bridge.index('nativeCe.applyAfterSavedAnalysis(program,')
    assert 'for (int dmPass = 0; dmPass < 2; dmPass++)' in bridge
    assert bridge.index('nativeCe.applyAfterSavedAnalysis(program,') < bridge.index('for (int dmPass = 0; dmPass < 2; dmPass++)')
    assert 'Sunplus DSP residual source-native DM16 pass' in bridge


def test_reset_bootstrap_discovers_real_native_vector_targets():
    source=(ROOT / "src/main/java/com/xebyte/sunplus/SunplusDspResetVectorBootstrap.java").read_text()
    assert 'for (int w = 4; w < word; w += 4)' in source
    assert 'irq.getFlows()[0]' in source
    assert 'irq.getFlowType().isComputed()' in source
    assert 'roots.add(branch)' in source
    assert 'program.getFunctionManager().getFunctionAt(vector)' in source
    assert 'PM:0be4' not in source


def test_codec_native_direct_reset_irq_page_source_proof():
    source = (ROOT / "src/main/java/com/xebyte/sunplus/SunplusDspResetVectorBootstrap.java").read_text()
    assert 'boolean maskControlReset' in source
    assert 'boolean directReset' in source
    assert 'jumpByte = maskControlReset ? 6 : 0' in source
    assert 'returns < 3 || branches < 1' in source
    assert 'handlerWord < word || handlerWord >= block.getSize() / 3' in source
    assert 'else return Result.absent(); // not a proven IRQ vector slot' in source
    assert 'word < 12 || word > 64' in source
    assert 'entryJump.getFlows().length != 1' in source
    assert 'program.endTransaction(tx, commit)' in source
    assert 'ac3-profile.bin' not in source and 'PM:2b4a' not in source


def test_nested_planner_requires_no_call_and_static_counter_writers():
    text=MODEL.read_text()
    assert 'planarTwoLevelNested(' in text
    assert 'staticCounterWriter(' in text
    assert 'if(group.outerWriter!=null' in text
    assert 'innerWriter==null' in text
    assert 'i.getFlowType().isCall()' in text
    assert 'sourceNestedFramesBalanced(' in text
    assert 'if (!commitChanges) {' in text
    assert 'hardware PC-stack proof UNKNOWN' in text
    assert 'plans.add(new NestedGroup(outer,outerWriter,children,writers))' in text


def test_nested_qa_protected_top_level_transaction():
    source=MODEL.read_text()
    assert 'RUSH28_NESTED_CE_QA' in source
    assert 'applyExperimentalNestedAfterSavedAnalysis' in source
    assert 'Nested QA C nonregression failed' in source
    assert 'program.endTransaction(tx,accept)' in source
    assert 'program.getRegister("codec_ce_counter14")' in source
    assert 'setValue(counter14,site.address,site.address,BigInteger.ONE)' in source
    assert 'if (site.end || sourceCounterWriter)' in source
    spec=(ROOT / 'processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec').read_text()
    assert 'CNTR = newval & 0x3fff;' in spec
    assert 'IntDst = IntSrc & 0x3fff;' in spec
    assert 'RUSH28_NESTED_CE_ABORT_AFTER_FIRST_QA' in source
    assert 'QA_FAULT_INJECTED_AFTER_NESTED_RECODE' in source
    assert 'hardware shared-PC-stack proof UNKNOWN' in source
    bridge=(ROOT / 'src/main/java/com/xebyte/core/ProgramScriptService.java').read_text()
    assert bridge.index('for (int dmPass = 0; dmPass < 2; dmPass++)') < bridge.index('nativeCe.applyExperimentalNestedAfterSavedAnalysis(')
    assert 'Sunplus DSP source-native two-level QA experiment' in bridge


def test_optin_native_ce_counter14_canonical_legacy_unchanged():
    spec=(ROOT / 'processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec').read_text()
    assert 'codec_ce_counter14=(29,29) noflow' in spec
    assert 'AluConst: 0x' not in spec
    assert 'AluConst: \"0x' in spec
    assert spec.count('codec_ce_counter14=1 & instruction')==9
    assert spec.count('codec_ce_counter14=0 & instruction')==9
    assert spec.count('CNTR = (CNTR - 1) & 0x3fff;')>=7
    assert 'codec_arch_stack_mode=1 & codec_ce_phase=0' in spec


def test_outer_counter_immediate_is_not_reencoded():
    source=MODEL.read_text()
    assert 'group.outerWriter.toString().trim().startsWith("LDI CNTR,")' in source
    assert 'only DM/register writers can' in source
    assert 'addNestedSite(sites,group.outerWriter,1,false,null);' in source


def test_ce_recovery_fails_closed_on_pc_stack_mutating_callees():
    code=MODEL.read_text()
    assert 'private static boolean mutatesControlStack(Instruction i)' in code
    assert 'op.contains("TOPPCSTACK")' in code
    assert 'op.contains("POP PC")' in code
    assert 'op.contains("POP LOOP")' in code
    assert 'op.contains("POP CNTR")' in code
    assert 'op.equals("RTI")' in code
    assert code.count('mutatesControlStack(i)') + code.count('mutatesControlStack(ins)') >= 2
    assert 'nativeCounterWrite(ins)' in code and 'mutatesControlStack(ins)' in code
    assert 'if(ins.getFlowType().isTerminal())return false;' in code
    assert 'returnsWithLocalDoFrames(' in code
    assert 'memo.put(key,returnReachable);' in code
    assert 'if(!f.getBody().contains(dst))return false;' in code
