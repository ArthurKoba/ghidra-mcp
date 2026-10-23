#!/usr/bin/env bash
# Headless-only Sunplus ISA regression against 11 independent native fixtures.
# No writes to canonical Analysis; each test owns an ephemeral Ghidra project.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?Local Ghidra installation required}"
: "${SUNPLUS_FIXTURE_OUT:?New non-existing output directory required}"
: "${SUNPLUS_FIXTURE_GROUP:=all}"
case "$SUNPLUS_FIXTURE_GROUP" in all|basic|nested|calls|arithmetic) ;; *) echo "Unknown fixture group" >&2; exit 2;; esac
if [[ -e "$SUNPLUS_FIXTURE_OUT" ]];then echo "Refuse existing output: $SUNPLUS_FIXTURE_OUT" >&2;exit 2;fi
if [[ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]];then echo "Missing local analyzeHeadless" >&2;exit 2;fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
base="$root/tests/fixtures/sunplus_sphe_audio_dsp"
lang="$GHIDRA_INSTALL_DIR/Ghidra/Processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.sla"
if [[ ! -s "$lang" ]];then echo "Missing compiled Sunplus processor model" >&2; exit 2;fi
mkdir -p "$SUNPLUS_FIXTURE_OUT/projects" "$SUNPLUS_FIXTURE_OUT/logs" "$SUNPLUS_FIXTURE_OUT/scripts"
case_for_group(){
  case "$SUNPLUS_FIXTURE_GROUP:$1" in
    all:*) return 0;;
    basic:single|basic:sequential|nested:nested2|nested:nested4|nested:nested_dm|nested:direct2|calls:call2|calls:call2stage|calls:condcall|arithmetic:signedshift|arithmetic:orshift|arithmetic:negse) return 0;;
    *) return 1;;
  esac
}
run_fixture(){
  local name="$1" fixture="$2" baseaddr="$3" script="$4" expected="$5"
  if ! case_for_group "$name";then return 0;fi
  local log="$SUNPLUS_FIXTURE_OUT/logs/$name.log" staged="$SUNPLUS_FIXTURE_OUT/scripts/$name"
  test -s "$base/$fixture.bin" && test -s "$root/ghidra_scripts/$script"
  mkdir -p "$staged"
  cp "$root/ghidra_scripts/$script" "$staged/"
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$SUNPLUS_FIXTURE_OUT/projects" "fixture-$name" \
    -import "$base/$fixture.bin" -loader BinaryLoader -loader-baseAddr "$baseaddr" \
    -processor "SunplusSPHEAudioDSP:BE:16:default" -cspec default \
    -noanalysis -scriptPath "$staged" -postScript "$script" -deleteProject > "$log" 2>&1 || {
      echo "HEADLESS_FAILED=$name" >&2;tail -24 "$log" >&2;exit 1;
    }
  if grep -Eq 'REPORT SCRIPT ERROR|SCRIPT ERROR|Exception in thread|ERROR Abort' "$log";then
    echo "SCRIPT_FAILED=$name" >&2;tail -24 "$log" >&2;exit 1;
  fi
  if ! grep -Fq "$expected" "$log";then
    echo "ACCEPTANCE_MISSING=$name expected=$expected" >&2;tail -24 "$log" >&2;exit 1;
  fi
  grep -F "$expected" "$log" | tail -1
}
run_fixture single pcm_ce_loop_12b8 0x12b8 SunplusDSPCeLoopRegression.java 'SUNPLUS_CODEC_CE_LOOP_ACCEPTANCE=PASS'
run_fixture sequential pcm_sequential_ce_07a4 0x7a4 SunplusPcmSequentialCeLoopAcceptance.java 'SUNPLUS_SEQUENTIAL_CE_ACCEPTANCE=PASS'
run_fixture nested2 nested_ce_2x3 0x100 SunplusNestedCeLoopAcceptance.java 'NESTED_CE_RUNTIME_ACCEPTANCE=PASS nested_ce_2x3.bin'
run_fixture nested4 nested_ce_4deep 0x200 SunplusNestedCeLoopAcceptance.java 'NESTED_CE_RUNTIME_ACCEPTANCE=PASS nested_ce_4deep.bin'
run_fixture nested_dm nested_ce_dmread_2x3 0x100 SunplusNestedCeLoopAcceptance.java 'NESTED_CE_RUNTIME_ACCEPTANCE=PASS nested_ce_dmread_2x3.bin'
run_fixture direct2 nested_ce_2x3 0x100 SunplusNestedDirectCeAcceptance.java 'SUNPLUS_NESTED_DIRECT_CE_RUNTIME_ACCEPTANCE=PASS'
run_fixture call2 nested_ce_call_2x3 0x300 SunplusNestedCallCeAcceptance.java 'CROSS_CALL_CE_PCODE_RETURN_ACCEPTANCE=PASS nested_ce_call_2x3.bin'
run_fixture call2stage nested_ce_call_2stage 0x300 SunplusNestedCallCeAcceptance.java 'CROSS_CALL_CE_PCODE_RETURN_ACCEPTANCE=PASS nested_ce_call_2stage.bin'
run_fixture condcall nested_ce_condcall_2x3 0x300 SunplusConditionalCeCallAcceptance.java 'CONDITIONAL_CE_CALL_ACCEPTANCE=PASS'
run_fixture signedshift immediate_signed_shift 0x400 SunplusSignedImmediateShiftAcceptance.java 'SUNPLUS_SIGNED_IMMEDIATE_SHIFT_ACCEPTANCE=PASS'
run_fixture orshift immediate_or_shift 0x500 SunplusOrImmediateShiftAcceptance.java 'SUNPLUS_OR_SHIFT_ACCEPTANCE=PASS'
run_fixture negse se_negative_type12 0x600 SunplusSeNegativeArithmeticAcceptance.java 'SE_NEGATIVE_ARITHMETIC_ACCEPTANCE=PASS variants=15'
echo "SUNPLUS_FIXTURES_${SUNPLUS_FIXTURE_GROUP}_PASS"
