"""Source guards for an opt-in, native-evidenced Sunplus DSP call convention."""
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
LANG=ROOT/'processors/SunplusSPHEAudioDSP/data/languages'
SCRIPT=ROOT/'ghidra_scripts/SunplusLoopSafeCallModel.java'


def test_default_callee_model_is_not_globally_made_loop_preserving() -> None:
    spec=ET.parse(LANG/'sunplus_sphe_audio_dsp.cspec').getroot()
    default=spec.find('default_proto/prototype')
    assert default is not None
    assert {r.attrib['name'] for r in default.findall('unaffected/register')}=={'PC','SP'}
    models=spec.findall('prototype')
    assert len([p for p in models if p.attrib.get('name')=='__sunplus_loop_safe'])==1
    special=next(p for p in models if p.attrib.get('name')=='__sunplus_loop_safe')
    assert {r.attrib['name'] for r in special.findall('unaffected/register')} == {
        'PC','SP','DSP_LOOP_START','DSP_LOOP_START_SHADOW','DSP_LOOP_COUNT_SHADOW'}
    assert special.find('input') is not None and special.find('output') is not None


def test_safe_loop_abi_application_requires_native_callee_proof_and_generated_c_improvement() -> None:
    source=SCRIPT.read_text()
    for invariant in ('getExecutableSHA256().equals(args[1])',
                      'nativeSafe(provider,new HashSet<>(),0)',
                      'singleLoop(loop,loops)',
                      'getCallingConvention(ABI)',
                      'setCallingConvention(ABI)',
                      'warnings(updated)',
                      'w1>w0', 'improved==0',
                      'currentProgram.endTransaction(tx,commit)',
                      'functionInventory',
                      'DSP_SAFE_ABI_APPLY_PASS'):
        # Function identity is checked through inventory(), not a raw address.
        if invariant == 'functionInventory':
            assert 'inventory()' in source
        else:
            assert invariant in source, invariant
    assert 'PM:0dff' not in source
    assert 'PM:0625' not in source
    assert 'ac3-profile.bin' not in source
    assert 'aux-profile.bin' not in source
    assert 'SunplusSPHEAudioDSP:BE:16:default' in source
