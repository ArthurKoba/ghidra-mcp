"""Source guards for native-proof-gated DSP conditional specialization.

Actual instruction execution and C/save/readback acceptance are performed by
registered Analyzer Java scripts on the isolated local Ghidra projects.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = (ROOT / "processors/SunplusSPHEAudioDSP/data/languages/"
        "sunplus_sphe_audio_dsp.slaspec").read_text()
TRUE = (ROOT / "ghidra_scripts/Rush26NativeProvenLeBranchRecovery.java").read_text()
FALSE = (ROOT / "ghidra_scripts/Rush26NativeProvenFalseBranchRecovery.java").read_text()


def test_native_semantic_rewrites_require_explicit_context() -> None:
    assert "codec_le_proven_taken=(26,26) noflow" in SPEC
    assert "codec_branch_proven_not_taken=(27,27) noflow" in SPEC
    assert 'codec_le_proven_taken=1 & type10=3 & call18=0 & cond4=3' in SPEC
    assert 'codec_branch_proven_not_taken=1 & type10=3 & call18=0 & cond4=3' in SPEC
    assert 'codec_branch_proven_not_taken=1 & type10=3 & call18=0 & cond4=1' in SPEC
    assert ':"IF LE JUMP" JumpAddr is codec_arch_stack_mode=0 & type10=3 & call18=0 & cond4=3 & JumpAddr' in SPEC
    assert ':"IF NE JUMP" JumpAddr is codec_arch_stack_mode=0 & type10=3 & call18=0 & cond4=1 & JumpAddr' in SPEC


def test_positive_proof_enforces_native_image_and_rollback() -> None:
    for token in ('pm(0x2630)', 'AF = AR - AY0', '0-7<0',
                  'currentProgram.getExecutableSHA256()', 'MessageDigest.getInstance("SHA-256")',
                  'currentProgram.endTransaction(tx,accepted)',
                  'PROVEN_LE_READBACK_PASS', 'need(now==0',
                  'currentProgram.getFunctionManager().getFunctionCount()==166'):
        assert token in TRUE, token


def test_negative_proof_enforces_both_native_predicates_and_rollback() -> None:
    for token in ('nativeIns(0x07c1', 'nativeIns(0x10f6', 'proveNoForeignEntry(0x07be,0x07c1)',
                  'proveNoForeignEntry(0x10f3,0x10f6)',
                  '0xffff>>>23', 'currentProgram.getExecutableSHA256()',
                  'currentProgram.endTransaction(tx,accept)',
                  'FALSE_BRANCH_READBACK_PASS', 'nowFirst==0&&nowSecond==0'):
        assert token in FALSE, token


def test_native_semantic_proofs_do_not_silence_c_warnings() -> None:
    for source in (TRUE, FALSE):
        assert 'split("WARNING:"' in source
        assert 'clearCodeUnits(' in source
        assert 'setValue(' in source
        assert 'DisassembleCommand' in source
        for forbidden in ('setFlowOverride(', 'clearReferencesTo(',
                          'setBytes(', 'suppressWarning', 'removeWarning'):
            assert forbidden not in source, forbidden
