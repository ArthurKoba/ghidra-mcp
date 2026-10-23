"""Source guards for scoped, native-backed DSP control-register side effects.

These checks do NOT stand in for Ghidra persisted readback or hardware proof.
"""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SRC=(ROOT/'ghidra_scripts/SunplusDSPControlRegisterVolatileRecovery.java').read_text()


def test_specific_control_register_not_globally_marked_volatile() -> None:
    for term in ('getExecutableSHA256()',
                 'mmio.getAddressableWordOffset()<0x3f00',
                 'mmio.getAddressableWordOffset()>0x3fff',
                 'reads<2||writes<2',
                 'verifiedLoops==0',
                 'mem.split(selected,mmio)',
                 'mem.split(selected,mmio.add(1))',
                 'selected.setVolatile(true)',
                 'selected.getSize()!=1',
                 'currentProgram.endTransaction(tx,accept)',
                 'DSP_MMIO_PROVEN_APPLY_PASS'):
        assert term in SRC, term
    assert 'DM:3f2c' not in SRC
    assert 'pcm-profile.bin' not in SRC
    assert 'LIKELY CONTROL REGISTER' in SRC
    assert 'hardware/external provider=UNKNOWN' in SRC


def test_independent_native_c_and_owner_noninterference_gates() -> None:
    for term in ('nativeFunctions()',
                 'countInstructions()',
                 'Arrays.equals(raw,hash())',
                 'warnings(code)',
                 'C_failed=0',
                 'improved==0',
                 'regressed!=0',
                 'warningOwners>=warningsBefore',
                 'currentProgram.getOptions("RUSH DSP MMIO Volatility")'):
        assert term in SRC, term
