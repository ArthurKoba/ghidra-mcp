"""Source guards for evidence-backed peripheral control-register side effects."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / 'ghidra_scripts/SunplusDSPControlRegisterVolatileRecovery.java').read_text()


def test_volatility_applies_only_to_one_native_verified_dsp_control_word() -> None:
    assert 'SunplusSPHEAudioDSP:BE:16:default' in SCRIPT
    assert 'getAddressableWordOffset()<0x3f00' in SCRIPT
    assert 'getAddressableWordOffset()>0x3fff' in SCRIPT
    assert 'if(reads<2||writes<2)' in SCRIPT
    assert 'if(verifiedLoops==0)' in SCRIPT
    assert 'mem.split(selected,mmio);' in SCRIPT
    assert 'mem.split(selected,mmio.add(1));' in SCRIPT
    assert 'selected.getSize()!=1' in SCRIPT
    assert 'selected.setVolatile(true)' in SCRIPT
    assert 'block.setVolatile(true)' not in SCRIPT
    assert 'DM:3f2c' not in SCRIPT.lower()


def test_mmio_requires_full_native_c_and_no_regression_for_acceptance() -> None:
    for invariant in (
        'getExecutableSHA256()',
        'startTransaction(',
        'currentProgram.endTransaction(tx,accept)',
        'Arrays.equals(raw,hash())',
        'fns.equals(nativeFunctions())',
        'instructions!=countInstructions()',
        'before.size()!=nativeTotal',
        'regressed!=0||warningOwners>=warningsBefore||improved==0',
        'DSP_MMIO_PROVEN_APPLY_PASS',
        'LIKELY CONTROL REGISTER',
        'hardware/external provider=UNKNOWN',
    ):
        assert invariant in SCRIPT, invariant
    assert 'if(mode.equals("audit"))' in SCRIPT
