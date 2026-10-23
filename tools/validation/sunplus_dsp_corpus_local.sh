#!/usr/bin/env bash
# Offline full-DSP regression. Never mutates the canonical Analysis project.
# Re-uses saved GZF snapshots, materializes projects, runs read-only C/P-code audits.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?local Ghidra installation required}"
: "${SUNPLUS_GZF_DIR:?directory containing five canonical GZF snapshots required}"
: "${SUNPLUS_CORPUS_OUT:?new output directory required}"
: "${SUNPLUS_CHECK_MODE:=baseline}"
# Explicit function-entry inventory in the exact order of the five GZF files.
# Defaults describe the old canonical snapshot; newer independently verified
# local checkpoints must supply their own counts (e.g. 9,68,115,165,103).
: "${SUNPLUS_FUNCTION_COUNTS:=9,61,115,37,100}"
case "$SUNPLUS_CHECK_MODE" in baseline|strict) ;; *) echo 'mode must be baseline or strict' >&2;exit 2;;esac
IFS=, read -r -a counts <<< "$SUNPLUS_FUNCTION_COUNTS"
if [[ "${#counts[@]}" -ne 5 ]];then echo 'expected five comma-separated function counts' >&2;exit 2;fi
for value in "${counts[@]}";do
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]];then echo "invalid function count: $value" >&2;exit 2;fi
done
if [[ -e "$SUNPLUS_CORPUS_OUT" ]];then echo "refusing existing output $SUNPLUS_CORPUS_OUT" >&2;exit 2;fi
if [[ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]];then echo 'Ghidra headless runner absent' >&2;exit 2;fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$SUNPLUS_CORPUS_OUT/projects" "$SUNPLUS_CORPUS_OUT/scripts" "$SUNPLUS_CORPUS_OUT/logs" "$SUNPLUS_CORPUS_OUT/c"
cp "$root/ghidra_scripts/SunplusDSPFullCorpusAcceptance.java" "$SUNPLUS_CORPUS_OUT/scripts/"
GH="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
index=0
for name in srvdsp.bin aux-profile.bin pcm-profile.bin ac3-profile.bin dts-profile.bin;do
  count="${counts[$index]}"
  index=$((index+1))
  gz="$SUNPLUS_GZF_DIR/$name.gzf"
  if [[ ! -f "$gz" ]];then echo "missing image $gz" >&2;exit 2;fi
  proj="SunplusLocalFull${name//[^[:alnum:]]/}"
  # The import step MUST have no mutating post-script. Ghidra can report a
  # successful save while changes from an import post-script are lost.
  "$GH" "$SUNPLUS_CORPUS_OUT/projects" "$proj" -import "$gz" -noanalysis > "$SUNPLUS_CORPUS_OUT/logs/$name.import.log" 2>&1 || {
    echo "import failed $name" >&2;tail -30 "$SUNPLUS_CORPUS_OUT/logs/$name.import.log" >&2;exit 1;
  }
  # Re-open the persisted program in a DISTINCT process; never derive
  # acceptance from in-memory, pre-save P-code.
  "$GH" "$SUNPLUS_CORPUS_OUT/projects" "$proj" -process "$name" -readOnly -noanalysis \
    -scriptPath "$SUNPLUS_CORPUS_OUT/scripts" \
    -postScript SunplusDSPFullCorpusAcceptance.java "$SUNPLUS_CHECK_MODE" "$SUNPLUS_CORPUS_OUT/c" "$count" \
    > "$SUNPLUS_CORPUS_OUT/logs/$name.audit.log" 2>&1 || {
      echo "audit failed $name" >&2;
      grep -E 'FULL_CORPUS_SUMMARY|FULL_CORPUS_FUNCTION|SCRIPT ERROR|Exception' "$SUNPLUS_CORPUS_OUT/logs/$name.audit.log" | tail -22 >&2 || true;
      exit 1;
    }
  grep 'FULL_CORPUS_SUMMARY' "$SUNPLUS_CORPUS_OUT/logs/$name.audit.log" | tail -1
  if [[ "$SUNPLUS_CHECK_MODE" == strict ]]; then
    grep -q 'FULL_CORPUS_ACCEPTANCE=PASS' "$SUNPLUS_CORPUS_OUT/logs/$name.audit.log"
  else
    grep -q 'FULL_CORPUS_BASELINE_CAPTURED=PASS' "$SUNPLUS_CORPUS_OUT/logs/$name.audit.log"
  fi
done
echo "SUNPLUS_DSP_FULL_CORPUS=${SUNPLUS_CHECK_MODE^^}_CAPTURED"
