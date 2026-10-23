"""Source guards for the proven native SE=-1/-2 DSP ASHIFT specialization.

The actual behavior proof is persisted in the local Ghidra synthetic/emulator
and 69-function AUX C readback project. Source guards avoid losing invariants.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SLEIGH = (ROOT/'processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.slaspec').read_text()
RECOVERY = (ROOT/'ghidra_scripts/SunplusDSPProvenNegativeSeRecovery.java').read_text()


def test_proven_se_negative_parallel_register_shift_is_context_gated() -> None:
    pattern=':SR "=" "ASHIFT" ShiftX "(LO)," DReg4 "=" DReg is codec_se_proven_negative=1 & op8=0x10 & sf4=6 & ShiftX & DReg4 & DReg'
    assert SLEIGH.count(pattern) == 1
    before,after=SLEIGH.split(pattern,1)
    body=after.split('\n}',1)[0]
    assert 'local moved:2 = DReg;' in body
    assert 'local src:4 = sext(ShiftX);' in body
    assert 'local magnitude:2 = -SE;' in body
    assert 'local result:4 = src s>> magnitude;' in body
    assert 'SR0 = result:2;' in body and 'SR1 = result[16,16];' in body
    assert 'DReg4 = moved;' in body
    # The generic path stays active for nonproven or potentially positive SE.
    assert ':SR "=" "ASHIFT" ShiftX "(LO)," DReg4 "=" DReg is op8=0x10 & sf4=6' in SLEIGH
    assert 'if(count s<0)' in SLEIGH


def test_native_flow_proof_does_not_fake_hardware_dispatch() -> None:
    for needed in ('getExecutableSHA256()', 'findNativeProvenLoops()',
                   'hasExtraIncoming(', 'loadBefore(', 'outputsSe(nativeIns)',
                   'nativeHash()', 'identities()', 'nativeCount()',
                   'currentProgram.endTransaction(tx,accepted)',
                   'conditional(specialized)!=originalBranches-1',
                   'signedRight(specialized)!=originalArithmeticShifts',
                   'DSP_SE_NEGATIVE_APPLY_PASS',
                   'hardware_execution=UNKNOWN'):
        assert needed in RECOVERY,needed
    assert 'PM:0ba3' not in RECOVERY
    assert 'aux-profile.bin' not in RECOVERY
    assert 'SE specialization must eliminate its dynamic conditional' in RECOVERY


def test_owner_and_noninterference_guards_are_universal() -> None:
    assert 'if(regressed!=0||warnOwners>oldWarnOwners||improved==0)' in RECOVERY
    assert 'if(!Arrays.equals(before,nativeHash())||!funcs.equals(identities())||instructions!=nativeCount())' in RECOVERY
    assert 'getProgramContext().setValue(negative,site.at(),site.at(),BigInteger.ONE)' in RECOVERY
    assert 'if(mode.equals("audit"))' in RECOVERY
