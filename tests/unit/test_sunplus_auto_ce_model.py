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
    assert 'code(last,PcodeOp.CBRANCH)>=1' in text
    assert 'code(last,PcodeOp.BRANCHIND)==1' in text
    assert 'alreadyDirect.signum() != 0' in text
    assert 'sourceLoopCountFlowBalanced(l,p,monitor)' in text
    assert 'cLoops(after)<cLoops(before)' in text
    assert 'cWarnings(after)>cWarnings(before)' in text
    assert 'cLoops(after)<cLoops(before)' in text
    assert 'program.endTransaction(tx,accepted)' in text


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
    assert source.index('QA_FAULT_INJECTED_AFTER_NATIVE_CE_RECODE') < source.index('DecompInterface nextC=new DecompInterface()')
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
    assert 'Native nested C nonregression failed' in source
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


def test_production_nested_architecture_has_atomic_source_and_c_gates():
    model=MODEL.read_text()
    bridge=(ROOT / "src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert "applyProvenNestedAfterSavedAnalysis(" in model
    assert "recoverNestedSourceFrames(program,monitor,log,false)" in model
    assert "sourceNestedFramesBalanced(outer,inside,program,monitor)" in model
    assert "sourceNestedFramesBalanced(outer,children,program,monitor)" in model
    assert "identities.put(f,f.getName()" in model
    assert 'cleanAfterRollback=' in model
    assert 'cWarnings(after)>cWarnings(before)' in model
    assert 'cLoops(after)<cLoops(before)' in model
    assert 'program.endTransaction(tx,accept)' in model
    assert 'qa && "1".equals(System.getenv("RUSH28_NESTED_CE_ABORT_AFTER_FIRST_QA"))' in model
    assert 'nativeCe.applyProvenNestedAfterSavedAnalysis(program,' in bridge
    assert bridge.index('nativeCe.applyAfterSavedAnalysis(program,') < bridge.index(
        'nativeCe.applyProvenNestedAfterSavedAnalysis(program,')
    assert bridge.index('nativeCe.applyProvenNestedAfterSavedAnalysis(program,') < bridge.index(
        'nativeCe.applyExperimentalNestedAfterSavedAnalysis(program,')


def test_source_native_atomic_returning_call_ce_is_model_pass():
    f=ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java"
    source=f.read_text()
    bridge=(ROOT/"src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert "MAX_NATIVE_RETURN_SCAN = 512" in source
    assert "if(++sourceDo>1)return false;" in source
    assert "f.getBody().contains(word(f.getProgram(),end))" in source
    assert "FlowOverride.CALL_RETURN" in source
    assert "sourceReachableNativeRts(provider,listing,monitor)" in source
    assert "other.first<=l.end" in source
    assert "PcodeOp.CALL" in source and "PcodeOp.BRANCHIND" in source
    assert "program.getProgramContext" not in source or "p.getProgramContext" in source
    assert "c(verify,before.getKey(),monitor)" in source
    assert "p.endTransaction(tx,commit)" in source
    assert "applyAfterSavedAnalysis(program," in bridge
    assert bridge.index("SunplusNativeReturningCallCeRecovery") < bridge.index(
        "nativeCe.applyAfterSavedAnalysis(program,")

def test_production_nested_followup_dm16_not_only_qa():
    bridge=(ROOT/"src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert 'boolean productionNestedChanged=program.isChanged();' in bridge
    assert 'if(productionNestedChanged || nestedChanged)' in bridge
    assert bridge.index('nativeCe.applyProvenNestedAfterSavedAnalysis(program,') < bridge.index(
        'if(productionNestedChanged || nestedChanged)')
    assert bridge.index('if(productionNestedChanged || nestedChanged)') < bridge.index(
        '"Sunplus DSP post-nested native DM16 pass "+')


def test_failed_recovery_does_not_silently_accept_clean_rollback():
    nested=MODEL.read_text()
    returning=(ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java").read_text()
    assert 'A rollback is integrity evidence, not acceptance evidence.' in nested
    assert 'Unknown/failed recovery is not an accepted architecture pass.' in returning
    assert '"UNKNOWN unresolved_CALL_RETURN_sites="' in returning

def test_source_owner_converges_after_nested_ce_in_one_analysis():
    source=(ROOT/"src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert source.count('SunplusNativeFlowOwnerRecovery.applyAfterSavedAnalysis(')==2
    assert source.index('Sunplus DSP final source-native PM ownership convergence') > source.index(
        'if(productionNestedChanged || nestedChanged)')
    assert source.index('Sunplus DSP final source-native PM ownership convergence') < source.index(
        'SunplusNativePollingMemoryRecovery.applyAfterSavedAnalysis(')

def test_missing_ce_context_is_source_proven_not_unconditional_guess():
    source=MODEL.read_text()
    assert 'boolean missingNativeCe=code(last,PcodeOp.BRANCHIND)==0' in source
    assert 'boolean nativeIndirectCe=code(last,PcodeOp.CBRANCH)>=1' in source
    assert '!last.getFlowType().isCall()' in source
    assert '!last.getFlowType().isComputed()' in source
    assert 'sourceLoopCountFlowBalanced(l,p,monitor)' in source
    assert 'int recovered=0,missing=0,rejected=0;' in source
    assert 'new Candidate(l,finish.getBytes(),missingCe,nativeCallTarget)' in source
    assert 'code(rendered,PcodeOp.BRANCHIND)!=0' in source

def test_release_native_requires_frozen_image_and_source_inventory():
    source=(ROOT/"ghidra_scripts/SunplusDSPFreshCodecCorpusAcceptance.java").read_text()
    assert 'mode.equals("strict-native")' in source
    assert 'args[3].equals(currentProgram.getExecutableSHA256())' in source
    assert 'ceCount!=sourceDO||sourceDecodedPm!=expectedDecodedPM' in source
    assert 'FULL_NATIVE_SOURCE_INVENTORY' in source
    assert 'strict&&(wrongDirectTarget!=0||withoutConditional!=0' in source

def test_native_return_discovery_models_proven_indirect_ce_two_successors():
    source=(ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java").read_text()
    assert 'sourceDoStart=-1,sourceDoEnd=-1' in source
    assert 'if(sourceDoEnd==(int)addr.getAddressableWordOffset())' in source
    assert 'opcode(ins,PcodeOp.CBRANCH)<1' in source
    assert 'opcode(ins,PcodeOp.BRANCHIND)' in source
    assert 'todo.add(successor);' in source and 'todo.add(repeated);' in source
    assert 'f.getBody().contains(successor)' in source

def test_release_native_rejects_unproven_composite_and_indirect_ce():
    source=(ROOT/"ghidra_scripts/SunplusDSPFreshCodecCorpusAcceptance.java").read_text()
    assert 'FULL_NATIVE_COMPOSITE_FLOW program=' in source
    assert 'verified_composite_ce_call_count' in source
    assert 'unresolved_invalid_native_flow_count' in source
    assert 'rawInvalidNativeFlow!=confirmed || unresolved!=0' in source
    assert 'unresolvedIndirectTarget!=0 || withIndirect!=0' in source

def test_single_loop_source_proof_must_actually_reach_ce():
    model=MODEL.read_text()
    start=model.index('private static boolean sourceLoopCountFlowBalanced(')
    end=model.index('private static boolean eligible(',start)
    code=model[start:end]
    assert 'boolean sourceCeReached=false;' in code
    assert 'sourceCeReached=true;' in code
    assert 'return sourceCeReached;' in code
    assert code.index('sourceCeReached=true;')<code.index('return sourceCeReached;')

def test_nested_production_does_not_abort_unrelated_native_owners():
    source=MODEL.read_text()
    start=source.index('private static boolean recoverNestedSourceFrames(')
    end=source.index('private static void addNestedSite(',start)
    code=source[start:end]
    assert 'Map<Function,Map<Address,NestedSite>> byOwner' in code
    assert 'new LinkedHashMap<>()' in code
    assert 'try {\n                    rewriteNestedSites(program,row.getValue(),monitor,false);' in code
    assert 'java.util.Collections.singletonMap(owner,previous.get(owner))' in code
    assert 'UNSUPPORTED owner ' in code
    assert 'program.endTransaction(tx,accept)' in code
    assert 'QA_FAULT_INJECTED_AFTER_NESTED_RECODE' in code
    assert 'if(qa)' in code

def test_general_returning_call_metadata_keeps_composite_ce_atomic():
    file=ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java"
    source=file.read_text()
    bridge=(ROOT/"src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert 'applyPlainReturningCallsAfterSavedAnalysis(' in source
    assert 'if(ceEnd.contains(next))continue;' in source
    assert '!owner.getBody().contains(next)' in source
    assert '!sourceReachableNativeRts(provider,listing,monitor)' in source
    assert 'provider.hasNoReturn()' in source
    assert 'old.setFlowOverride(FlowOverride.NONE);' in source
    assert 'p.endTransaction(tx,accepted)' in source
    assert 'updated=c(after,affectedFunction,monitor)' in source
    assert bridge.count('applyPlainReturningCallsAfterSavedAnalysis(program,')==2
    assert bridge.index('applyPlainReturningCallsAfterSavedAnalysis(program,') < bridge.index(
        'SunplusNativeReturningCallCeRecovery\n                    .applyAfterSavedAnalysis(program,')

def test_ordinary_call_recovery_rejects_bad_c_per_owner_not_whole_profile():
    source=(ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java").read_text()
    start=source.index('private static boolean restorePlainReturningCalls(')
    end=source.index('private static boolean run(',start)
    ordinary=source[start:end]
    assert 'UNSUPPORTED original C ' in ordinary
    assert 'continue;' in ordinary[ordinary.index('UNSUPPORTED original C '):
                                   ordinary.index('int originalCount=fm.getFunctionCount()')]
    assert 'sourceReachableNativeRts(provider,listing,monitor)' in ordinary
    assert 'if(ceEnd.contains(next))continue;' in ordinary

def test_compound_native_call_ce_must_preserve_original_machine_call():
    model=MODEL.read_text()
    assert 'boolean nativeCallCeCandidate=false;' in model
    assert '"NONE".equals(last.getFlowOverride().name())' in model
    assert 'returnsViaSharedPcStack(provider,listing,p.getFunctionManager(),' in model
    assert 'new Candidate(l,finish.getBytes(),missingCe,nativeCallTarget)' in model
    assert 'if(candidate.nativeCallTarget!=null)' in model
    assert '"Composite native CALL target changed "' in model

def test_native_ce_owner_rejection_verifies_context_rollback():
    source=MODEL.read_text()
    assert 'snapshotNativeNestedContexts(program,row.getValue())' in source
    assert 'assertNestedSourceRollback(program,row.getValue(),' in source
    assert 'UNSUPPORTED nested owner rollback leaked processor context' in source
    assert 'UNSUPPORTED nested owner rollback changed source/CFG at ' in source
    assert 'if(state.pendingCounter()||nativeCounterWrite(ins))return false;' in source

def test_fresh_qa_corpus_accepts_exact_six_parameter_native_scope():
    source=(ROOT/"ghidra_scripts/SunplusDSPFreshCodecCorpusAcceptance.java").read_text()
    assert 'if(expected==null && args.length>=4 &&' in source
    assert 'if(releaseNative && (args.length!=6 ||' in source
    assert 'sourceDecodedPm!=expectedDecodedPM' in source

def test_failed_production_owner_transactions_verify_native_cfg_metadata():
    nested=MODEL.read_text()
    returning=(ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java").read_text()
    assert 'UNSUPPORTED nested owner rollback leaked function identity' in nested
    assert 'UNSUPPORTED returning CALL rollback leaked owner metadata' in returning
    assert 'UNSUPPORTED returning CALL rollback leaked CFG at ' in returning
    assert 'restored.getFlowOverride()!=FlowOverride.CALL_RETURN' in returning


def test_stale_noreturn_is_fixed_with_source_call_and_all_direct_consumers():
    source=(ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java").read_text()
    start=source.index('private static boolean restorePlainReturningCalls(')
    end=source.index('private static boolean run(',start)
    method=source[start:end]
    assert '!sourceReachableNativeRts(provider,listing,monitor)' in method
    assert 'provider.hasNoReturn()||' not in method
    assert 'Map<Address,Function> callProviders=' in method
    assert 'if(provider.hasNoReturn())provider.setNoReturn(false);' in method
    assert 'affected.add(owner)' in method
    assert 'affected.addAll(providers)' in method
    assert 'for(Instruction candidate:listing.getInstructions(true))' in method
    assert 'for(Function affectedFunction:affected)' in method
    assert 'Native CALL consumer C regression ' in method
    assert 'UNSUPPORTED returning CALL rollback leaked provider metadata' in method


def test_proven_native_conditional_rts_checks_taken_return_and_fallthrough():
    source=(ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java").read_text()
    start=source.index('private static boolean sourceReachableNativeRts(')
    end=source.index('private static List<Candidate> discover(',start)
    flow=source[start:end]
    assert 'text.startsWith("IF ")&&text.endsWith(" RTS")' in flow
    assert '!ins.getFlowType().isConditional()' in flow
    assert 'opcode(ins,PcodeOp.RETURN)!=1' in flow
    assert '!f.getBody().contains(fall)' in flow
    assert 'todo.add(fall);' in flow
    assert 'found=true;' in flow


def test_nested_dsp_ce_source_missing_pcode_is_a_proven_eligible_shape():
    source=MODEL.read_text()
    assert 'private static boolean nativeCeRecoverable(' in source
    assert 'boolean missingContext=code(end,PcodeOp.BRANCHIND)==0' in source
    assert '!end.getFlowType().isComputed()' in source
    assert '!end.getFlowType().isCall()' in source
    assert '!end.getFlowType().isJump()' in source
    assert 'nativeCounterWrite(end)||mutatesControlStack(end)' in source
    assert 'reachedCeEnds.containsAll(ends.keySet())' in source


def test_bounded_counted_callee_uses_native_rts_not_cached_noreturn_flag():
    source=MODEL.read_text()
    begin=source.index('private static boolean balancedCountConsumer(')
    end=source.index('private static boolean sourceResetStackHandler(',begin)
    contract=source[begin:end]
    assert 'if(f==null||f.isExternal())return false;' in contract
    assert 'if(f==null||f.isExternal()||f.hasNoReturn())return false;' not in contract
    assert 'code(ins,PcodeOp.RETURN)!=1' in contract
    assert 'if(!returned||counted==null)return false;' in contract


def test_nested_ce_never_confuses_native_call_or_return_composite():
    source=MODEL.read_text()
    start=source.index('private static boolean nativeCeRecoverable(')
    end=source.index('private static List<NestedGroup> planarTwoLevelNested(',start)
    helper=source[start:end]
    assert 'code(end,PcodeOp.CALL)!=0||code(end,PcodeOp.RETURN)!=0' in helper
    assert 'end.getFlowType().isCall()||end.getFlowType().isTerminal()' in helper


def test_native_ce_is_owner_local_atomic_with_verified_rollback():
    source=MODEL.read_text()
    start=source.index('private static boolean run(Program program')
    end=source.index('private static String getClassName()',start)
    run=source[start:end]
    assert 'for(var ownerEntry:perOwner.entrySet())' in run
    assert 'Map<Address,List<BigInteger>> contextBefore=' in run
    assert 'UNSUPPORTED native CE rollback leaked P-code context' in run
    assert 'recovered+=ownerCandidates.size();' in run
    assert 'rejected+=ownerCandidates.size();' in run
    assert 'cWarnings(after)>cWarnings(before)' in run
    assert 'cLoops(after)<cLoops(before)' in run
    assert 'program.endTransaction(tx,accepted)' in run


def test_nested_invalid_c_baseline_isolated_to_owning_function():
    model=MODEL.read_text()
    start=model.index('private static boolean recoverNestedSourceFrames(')
    end=model.index('private static Map<Address,List<BigInteger>> snapshotNativeNestedContexts(',start)
    fragment=model[start:end]
    assert 'Set<Function> missingBaselineOwners=new LinkedHashSet<>()' in fragment
    assert 'if(qa)throw unavailable;' in fragment
    assert 'missingBaselineOwners.add(f);' in fragment
    assert 'if(missingBaselineOwners.contains(owner))' in fragment
    assert 'rejectedOwners++;' in fragment


def test_bounded_final_ce_converges_after_function_and_call_metadata():
    source=(ROOT/"src/main/java/com/xebyte/core/ProgramScriptService.java").read_text()
    assert source.count("nativeCe.applyAfterSavedAnalysis(program,")==2
    assert source.index("Sunplus DSP late proven native CALL continuations") < source.index(
        "Sunplus DSP final source-native CE convergence")
    assert source.index("Sunplus DSP final source-native CE convergence") < source.index(
        "SunplusNativePollingMemoryRecovery.applyAfterSavedAnalysis(")
    assert 'boolean lateCeChanged=program.isChanged();' in source
    assert 'if(lateCeChanged)' in source


def test_native_ce_rollback_compares_original_pcode_and_cfg():
    source=MODEL.read_text()
    assert 'private static String nativeFlowSignature(Instruction i)' in source
    assert 'originalFlow.put(at,nativeFlowSignature(' in source
    assert '!originalFlow.get(at).equals(nativeFlowSignature(restored))' in source
    assert 'originalFlows.put(site.address,nativeFlowSignature(' in source
    assert '!originalFlows.get(site.address).equals(nativeFlowSignature(restored))' in source


def test_atomic_native_call_ce_checks_all_direct_abi_consumers_not_all_functions():
    source=(ROOT/"src/main/java/com/xebyte/sunplus/SunplusNativeReturningCallCeRecovery.java").read_text()
    start=source.index('private static boolean run(')
    body=source[start:]
    assert 'affected.add(next.loop.owner);' in body
    assert 'affected.add(next.provider);' in body
    assert 'if(provider==null||!allowedNoReturnChanges.contains(provider))' in body
    assert 'affected.add(caller);' in body
    assert 'if(affected.size()>96)' in body
    assert 'for(Function f:affected)' in body
    assert 'for(Function f:fm.getFunctions(true))' not in body

def test_original_machine_call_with_computed_ce_uses_real_call_pcode_target():
    source=MODEL.read_text()
    assert '"INVALID".equals(last.getFlowType().toString())' in source
    assert 'code(last,PcodeOp.BRANCHIND)<=1' in source
    assert 'target=op.getInput(0).getAddress();' in source
    assert 'if(op.getOpcode()==PcodeOp.CALL)' in source
    assert 'nativeCallTarget=op.getInput(0).getAddress();' in source
    assert 'returnsViaSharedPcStack(provider,listing,p.getFunctionManager(),' in source
