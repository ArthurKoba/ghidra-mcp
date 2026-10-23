"""Prevent regressions in the generic Ghidra native shared-handler model."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
JAVA=(ROOT/'ghidra_scripts/SunplusDSPSharedTailcallRecovery.java').read_text()


def test_shared_exception_rule_has_native_provenance_and_no_magic_addresses() -> None:
    assert 'private record Candidate(Address start,Address end,Function parent' in JAVA
    assert 'crossOwnerJumpEntries()' in JAVA
    assert 'owners.size()<3||foreignOwners<3' in JAVA
    assert 'if(inbound.size()<6' in JAVA
    assert 'Function owning=fm.getFunctionContaining(target)' in JAVA
    assert 'start.addNoWrap(w*3L)' in JAVA
    assert 'i.getFlowType().isJump()' in JAVA
    assert 'i.getFlows()' in JAVA
    assert 'SourceType.ANALYSIS' in JAVA
    assert not re.search(r'PM:(?:0x)?[0-9a-f]{3,}',JAVA,re.IGNORECASE)
    assert 'ac3-profile.bin' not in JAVA
    assert 'pm0140' not in JAVA.lower()


def test_shared_tailcall_requires_all_conditional_pcode_predicates_unchanged() -> None:
    for expected in (
        'List<String> predicate=conditions(i)',
        'i.setFlowOverride(FlowOverride.CALL_RETURN)',
        'conditions(i).equals(site.predicatePcode())',
        'nativeDigest()',
        'immutableFunctionIdentity()',
        'warnings(output)',
        'regressed!=0||improved==0||owners>=priorAffected',
        'currentProgram.endTransaction(tx,commit)',
        'DSP_SHARED_TAILCALL_APPLY_PASS',
        'getExecutableSHA256()',
    ):
        assert expected in JAVA, expected


def test_shared_handler_never_rewrites_known_resident_bootstrap() -> None:
    assert 'currentProgram.getName().equals("srvdsp.bin")' in JAVA
    assert 'if(mode.equals("audit"))' in JAVA
    assert 'if(eligible.size()!=1)' in JAVA
    assert 'native_added=1' in JAVA
