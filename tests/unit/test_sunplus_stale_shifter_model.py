"""Prevent generalized Sunplus stale negative-shift semantics regressions."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SRC=(ROOT/'ghidra_scripts/SunplusDSPStaleShifterRecovery.java').read_text()


def test_negative_shift_is_source_verified_and_not_address_hardcoded() -> None:
    assert 'SunplusSPHEAudioDSP:BE:16:default' in SRC
    assert 'INT_LEFT' in SRC and 'INT_RIGHT' in SRC and 'INT_SRIGHT' in SRC
    assert 'int encodedShift=256-negativeByte;' in SRC
    assert 'if(negativeByte<=0x80)continue;' in SRC
    assert 'currentProgram.getFunctionManager().getFunctionContaining' in SRC
    assert 'candidate.arithmetic()?PcodeOp.INT_SRIGHT:PcodeOp.INT_RIGHT' in SRC
    assert 'PM:23f0' not in SRC and 'ac3-profile.bin' not in SRC
    assert 'SHADOW' not in SRC


def test_mutation_requires_same_machine_bytes_function_bodies_and_full_C() -> None:
    for term in ('getExecutableSHA256()', 'currentProgram.startTransaction(',
                 'currentProgram.endTransaction(tx,accepted)',
                 'Arrays.equals(sourceHash,nativeHash())',
                 'inventory.equals(functionInventory())',
                 'afterInstructions!=instructionCount',
                 'c(check,f)', 'baseline.size()!=nativeTotal',
                 'w1>w0', 'regressed!=0||newWarnOwners>baselineOwners',
                 'options', 'DSP_SHIFT_STALE_APPLY_PASS'):
        if term=='options':
            assert 'getOptions("RUSH DSP Stale Shift Recovery")' in SRC
        else:
            assert term in SRC,term
    assert 'if(mode.equals("audit"))' in SRC
    assert 'if(!accepted)' in SRC
    assert 'CONFIRMED-STATIC' in SRC and 'hardware execution UNKNOWN' in SRC
