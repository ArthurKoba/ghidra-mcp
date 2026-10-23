"""Source-level guards for the explicit Sunplus DSP architecture recovery passes.

These checks do not replace Ghidra headless integration, saved-program
readback, PM24 emulation or hardware-equivalence tests.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "ghidra_scripts"


def read(name: str) -> str:
    return (SCRIPTS / name).read_text(encoding="utf-8")


def test_structural_ce_pass_is_based_on_do_operands_not_addresses() -> None:
    src = read("SunplusDSPStructuralRecovery.java")
    assert 'Pattern.compile("^DO' in src
    assert "Address expected=pm(begin+1)" in src
    assert "State.INDIRECT" in src
    assert "State.WRONG_DIRECT" in src
    assert "State.NESTED" in src
    # Both parent AND child of a strict DO containment require a nested
    # hardware-stack proof; the generic non-nested pass must not recode either.
    assert "participatesInNesting=true; // this DO is an inner loop" in src
    assert "participatesInNesting=true; // this DO is an OUTER loop" in src
    assert "else if(participatesInNesting){state=State.NESTED;" in src
    assert "State.COUNTER_HAZARD" in src
    assert "State.CALL_HAZARD" in src
    assert 'mode.equals("audit")' in src
    assert 'mode.equals("apply-safe")' in src
    assert "startTransaction(" in src and "endTransaction(tx,commit)" in src
    assert "initializedSHA()" in src
    assert "functions()" in src
    assert "cWarnings(after)>cWarnings(prior)" not in src  # compare old/new per function
    assert "newWarn>oldWarn" in src
    assert "PM:19e9" not in src and "PM:1bf9" not in src
    assert "PM:03d7" not in src and "FUN_PM_" not in src


def test_nested_loop_pass_requires_hardware_count_and_leaf_proof() -> None:
    src = read("SunplusDSPNestedLoopRecovery.java")
    assert 'Pattern.compile("^DO' in src
    assert "contains(outer,inner)" in src
    assert "verifiedLeafCall(inst)" in src
    assert "inst.getFlowType().isComputed()" in src
    assert "inst.toString().trim().equals(\"RTS\")" in src
    assert '"DSP_STATIC_CNTR_OUTER"' in src
    assert 'context("codec_ce_static_depth")' in src
    assert 'context("codec_ce_nested_mode")' in src
    assert "if(!preserves)" in src
    assert "markEnd(p.inner(),2," in src
    assert "markEnd(p.outer(),1," in src
    assert "startTransaction(" in src and "endTransaction(tx,commit)" in src
    assert "c1<c0+needed.get(e.getKey())" in src
    assert "PM:0462" not in src and "PM:0474" not in src
    assert "PM:2513" not in src


def test_dm_word_pass_infers_width_from_decompiler_and_native_pcode() -> None:
    src = read("SunplusDSPDmWidthRecovery.java")
    assert "Globals starting with" in src
    assert 'code==PcodeOp.LOAD' in src
    assert "op.getInput(1).isConstant()" in src
    assert "op.getInput(0).getOffset()!=spaceId" in src
    assert "width!=2" in src
    assert "currentProgram.getSymbolTable().getGlobalSymbols(symbol)" in src
    assert "SourceType.USER_DEFINED" in src
    assert "Undefined2DataType.dataType" in src
    assert "createUninitializedBlock(" in src
    assert "b.setComment(" in src
    assert "isVolatile()" in src
    assert "getDataType().getName().equals(\"undefined\")" in src
    assert "label.getName()" in src and "label.getSource()" in src
    assert "newWarn>oldWarn" not in src
    assert "result.overlapFunctions()>=baseline.overlapFunctions()" in src
    assert "result.doLoops()<baseline.doLoops()" in src
    assert 'mode.equals("audit")' in src
    assert "startTransaction(" in src and "endTransaction(tx,commit)" in src
    assert "0x3c14" not in src and "0x002c" not in src
    assert "DM:3f" not in src and "DAT_DM_0b14" not in src


def test_design_doc_distinguishes_gzf_proof_from_isa_and_encoder() -> None:
    path = ROOT / "docs/project-management/SUNPLUS_DSP_ARCHITECTURE_RECOVERY.md"
    design = path.read_text(encoding="utf-8")
    readme = (ROOT / "processors/SunplusSPHEAudioDSP/README.md").read_text()
    assert "SunplusDSPStructuralRecovery.java" in design
    assert "SunplusDSPNestedLoopRecovery.java" in design
    assert "SunplusDSPDmWidthRecovery.java" in design
    assert "audit" in design and "apply-safe" in design
    assert "16-bit" in design and "24-bit" in design
    assert "not an assembler" in design.lower()
    assert "decode -> normalize -> encode" in design
    assert "SUNPLUS_DSP_ARCHITECTURE_RECOVERY.md" in readme


def test_strict_corpus_checks_direct_ce_target_not_just_branch_shape() -> None:
    acceptance = read("SunplusDSPFullCorpusAcceptance.java")
    assert "Address expectedBackedge=inst.getFallThrough();" in acceptance
    assert "matchedDirect++" in acceptance
    assert "wrongDirectTarget++" in acceptance
    assert "ce_wrong_direct_target=" in acceptance
    assert "ce_unresolved_indirect_target=" in acceptance
    assert "strict&&(wrongDirectTarget!=0" in acceptance


def test_poll_word_addresses_and_async_contract_gate() -> None:
    source = read("SunplusDSPHandshakePollRecovery.java")
    assert "Math.multiplyExact(wordAddress,(long)space.getAddressableUnitSize())" in source
    assert "address.getAddressableWordOffset()!=wordAddress" in source
    assert "inferred polling alone cannot authorize volatile memory" in source
    assert source.index('if(mode.equals("apply-safe"))') < source.index('List<Candidate> proposals=')
    assert 'DSP_POLL_CANDIDATE owner=' in source
