"""Guard the separately executable Sunplus DSP software-sequencer model.

The actual machine-instruction execution gate is SunplusArchitecturalStackAcceptance
in isolated Ghidra; these checks prevent unintentional ISA/legacy ABI changes.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANG = ROOT / "processors/SunplusSPHEAudioDSP/data/languages"
MODEL = (LANG / "sunplus_sphe_audio_dsp.slaspec").read_text()
RUNTIME = (LANG / "sunplus_stack_runtime.sinc").read_text()
OPS = (LANG / "sunplus_stack_instructions.sinc").read_text()
SCRIPT = (ROOT / "ghidra_scripts/SunplusArchitecturalStackAcceptance.java").read_text()


def test_new_shared_stack_mode_is_opt_in_and_preserves_legacy_mode() -> None:
    assert 'codec_arch_stack_mode=(28,28) noflow' in MODEL
    assert '@include "sunplus_stack_runtime.sinc"' in MODEL
    assert '@include "sunplus_stack_instructions.sinc"' in MODEL
    assert 'codec_arch_stack_mode=0 & codec_ce_loop_end=1' in MODEL or 'codec_arch_stack_mode=0 & codec_ce_phase=0 & codec_ce_loop_end=1' in MODEL
    assert 'codec_arch_stack_mode=1 & codec_ce_phase=0' in MODEL
    assert 'codec_arch_stack_mode=1 & type10=3' in OPS
    assert 'codec_arch_stack_mode=1 & type11=5' in OPS


def test_stack_memory_is_separate_from_native_pm_dm() -> None:
    assert 'define space DSPSTACK type=ram_space size=2;' in RUNTIME
    assert 'define space PM       type=ram_space      size=2 wordsize=3 default;' in MODEL
    assert 'define space DM       type=ram_space      size=2 wordsize=2;' in MODEL
    assert '*[DSPSTACK]:2' in RUNTIME
    assert '*[DSPSTACK]:4' in RUNTIME


def test_shared_stack_and_failure_paths_have_explicit_contracts() -> None:
    assert 'DSP_PC_DEPTH<16' in RUNTIME
    assert 'DSP_ARCH_LOOP_DEPTH<4' in RUNTIME
    assert 'DSP_ARCH_COUNT_DEPTH<4' in RUNTIME
    assert 'DSP_STATUS_DEPTH<12' in RUNTIME
    assert 'dsp_model_stack_fault(kind);' in RUNTIME
    for fault in ('arch_stack_error(1:2)', 'arch_stack_error(2:2)',
                  'arch_stack_error(3:2)', 'arch_stack_error(4:2)',
                  'arch_stack_error(5:2)', 'arch_stack_error(6:2)',
                  'arch_stack_error(7:2)', 'arch_stack_error(8:2)'):
        assert fault in RUNTIME, fault


def test_rti_status_restoration_and_bank_swap_are_not_noops() -> None:
    for item in ('macro arch_status_push()', 'macro arch_status_pop()',
                 'macro arch_astat_write(value)', 'macro arch_mstat_write(value)',
                 'arch_bank_swap(AX0,DSP_ALT_AX0)', 'DSP_PC_POP_PENDING',
                 'macro arch_complete_pending_pc()'):
        assert item in RUNTIME, item
    assert '"RTI"' in OPS
    assert 'arch_status_pop();' in OPS
    assert '"CALL"' in OPS and '"RTS"' in OPS


def test_native_execution_acceptance_rejects_regressions() -> None:
    for required in ('SOFTWARE_STACK_MODEL_PASS', 'SOFTWARE_SEQUENCER_TESTS_PASSED',
                     'shared-PC16-CALL-DO', 'counter-stack-OWRCNTR',
                     'nested-DO-CE', 'mixed-CALL-DO-RTI',
                     'all-DO-termination-flags', 'RTI-all-condition-flags',
                     'CALL-all-condition-flags', 'combined-POP-and-delayed-TOPPC',
                     'SOFTWARE_STACK_MODEL_RESULT', 'currentProgram.isChanged()',
                     'getExecutableSHA256()' if 'getExecutableSHA256()' in SCRIPT else 'nativeHash()'):
        assert required in SCRIPT, required
    assert 'getOptions(group).setString(key,json)' in SCRIPT
    assert 'getOptions(group).getString(key,' in SCRIPT
    assert 'new PcodeEmulator(language)' in SCRIPT
