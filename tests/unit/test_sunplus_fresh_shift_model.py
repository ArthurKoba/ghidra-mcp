"""Native saved SLEIGH P-code refresh must be distinct from patching firmware."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SOURCE=(ROOT/'ghidra_scripts/SunplusDSPFreshShiftRecovery.java').read_text()
AUDIT=(ROOT/'ghidra_scripts/SunplusDSPFreshPcodeAudit.java').read_text()


def test_fresh_shift_refresh_has_no_codec_specific_native_addresses() -> None:
    assert 'SunplusSPHEAudioDSP:BE:16:default' in SOURCE
    assert 'new ByteMemBufferImpl' in SOURCE
    assert 'new ProcessorContextImpl(language)' in SOURCE
    assert 'getContextRegisters()' in SOURCE
    assert 'language.parse(buffer,context,false)' in SOURCE
    assert 'new PseudoInstruction' in SOURCE
    assert 'currentProgram.getExecutableSHA256()' in SOURCE
    assert 'getFunctionContaining(i.getAddress())' in SOURCE
    assert 'LSHIFT|ASHIFT' in SOURCE
    for string in ('PM:23f0','PM:0905','ac3-profile.bin','pcm-profile.bin'):
        assert string not in SOURCE


def test_redecode_requires_shift_sign_and_new_pcode_identity() -> None:
    for term in ('int signed=(byte)raw[2]',
                 'signed!=visible',
                 'PcodeOp.INT_LEFT',
                 'PcodeOp.INT_RIGHT',
                 'PcodeOp.INT_SRIGHT',
                 '!shift.updated().equals(pcode(newer))',
                 'Arrays.equals(newer.getBytes(),shift.encoded())',
                 'currentProgram.endTransaction(tx,commit)'):
        assert term in SOURCE,term
    assert 'origina' in SOURCE
    assert 'C_ok=' in SOURCE
    assert 'halt_baddata()' in SOURCE
    assert 'if(regressions!=0||warningsAfter>ownersBefore)' in SOURCE
    assert 'DSP_FRESH_SHIFT_AUDIT_PASS' in SOURCE
    assert 'DSP_FRESH_SHIFT_APPLY_PASS' in SOURCE


def test_separate_native_pcode_audit_is_readonly_and_checksum_guarded() -> None:
    assert 'currentProgram.isChanged()!=modified' in AUDIT
    assert 'getDomainFile().getVersion()!=version' in AUDIT
    assert 'Pcode_discrepancies' in AUDIT
    assert 'parse_failures' in AUDIT
    assert 'REFUSE' not in AUDIT.upper() or 'Refuse overwrite' in AUDIT
    assert 'Files.exists(report)' in AUDIT
