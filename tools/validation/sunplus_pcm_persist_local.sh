#!/usr/bin/env bash
# Explicit local-only, write-then-reopen acceptance on a CLONED Ghidra project.
# Never points the write-mode headless runner at the source project itself.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to a local Ghidra 12.1.3 installation}"
: "${PCM_GHIDRA_PROJECT_DIR:?Set PCM_GHIDRA_PROJECT_DIR to a directory containing the preserved .gpr/.rep}"
: "${PCM_GHIDRA_PROJECT_NAME:=PcmOrShiftAudit}"
: "${PCM_PROGRAM_NAME:=pcm_current115}"
: "${PCM_TEST_OUT:?Set PCM_TEST_OUT to a NEW empty directory for test artifacts}"
if [[ -e "$PCM_TEST_OUT" ]]; then
  echo "Refusing existing output directory: $PCM_TEST_OUT" >&2
  exit 2
fi
if [[ ! -f "$PCM_GHIDRA_PROJECT_DIR/$PCM_GHIDRA_PROJECT_NAME.gpr" ||
      ! -d "$PCM_GHIDRA_PROJECT_DIR/$PCM_GHIDRA_PROJECT_NAME.rep" ]]; then
  echo "Preserved Ghidra project pair not found" >&2
  exit 2
fi
if [[ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]]; then
  echo "analyzeHeadless is missing" >&2
  exit 2
fi
# A previously installed Sunplus language may use the OLD .sla even with a
# matching Ghidra version. Require the verified Type-12 SE-enabled compiler
# output before testing the preserved PCM project.
required_sla_sha256="333b3f54463e5bb35c782d3b9195ec4439e63fe735f0de929b454daab4d51a17"
sla="$GHIDRA_INSTALL_DIR/Ghidra/Processors/SunplusSPHEAudioDSP/data/languages/sunplus_sphe_audio_dsp.sla"
if [[ ! -f "$sla" ]] || [[ "$(sha256sum "$sla" | cut -d' ' -f1)" != "$required_sla_sha256" ]]; then
  echo "Expected exact tested SE-enabled Sunplus .sla; wrong/stale processor language" >&2
  exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$PCM_TEST_OUT/projects" "$PCM_TEST_OUT/validation_scripts"
cp -a "$PCM_GHIDRA_PROJECT_DIR/$PCM_GHIDRA_PROJECT_NAME.gpr" "$PCM_TEST_OUT/projects/"
cp -a "$PCM_GHIDRA_PROJECT_DIR/$PCM_GHIDRA_PROJECT_NAME.rep" "$PCM_TEST_OUT/projects/"
# Ghidra's Java script provider compiles all .java files in a script directory.
# Stage ONLY the two reviewed sources: legacy ghidra_scripts may contain
# unrelated scripts whose API is incompatible with the current Ghidra SDK.
cp "$repo_root/ghidra_scripts/SunplusPcmSePersistMigration.java" "$PCM_TEST_OUT/validation_scripts/"
cp "$repo_root/ghidra_scripts/SunplusPcmSePersistReadback.java" "$PCM_TEST_OUT/validation_scripts/"
ghidra="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
common=("$PCM_TEST_OUT/projects" "$PCM_GHIDRA_PROJECT_NAME" -process "$PCM_PROGRAM_NAME" -noanalysis -scriptPath "$PCM_TEST_OUT/validation_scripts")
"$ghidra" "${common[@]}" -postScript SunplusPcmSePersistMigration.java \
  > "$PCM_TEST_OUT/migration.log" 2>&1
if grep -Eq 'SCRIPT ERROR|REPORT SCRIPT ERROR|Exception in thread' "$PCM_TEST_OUT/migration.log" ||
   ! grep -q 'RUSH_PCM_SE_MIGRATION_ACCEPTANCE=PASS' "$PCM_TEST_OUT/migration.log" ||
   ! grep -q 'RUSH_PCM_SE_MIGRATION_COMMITTED=true' "$PCM_TEST_OUT/migration.log"; then
  echo "Write-mode migration failed; inspect $PCM_TEST_OUT/migration.log" >&2
  exit 1
fi
# Distinct headless process reloads the SAVED project, without replaying the mutation.
"$ghidra" "${common[@]}" -readOnly -postScript SunplusPcmSePersistReadback.java \
  > "$PCM_TEST_OUT/reopen.log" 2>&1
if grep -Eq 'SCRIPT ERROR|REPORT SCRIPT ERROR|Exception in thread' "$PCM_TEST_OUT/reopen.log" ||
   ! grep -q 'SUNPLUS_PCM_PERSIST_READBACK=PASS warnings=0/0 gm5_loops=8 functions=115' "$PCM_TEST_OUT/reopen.log"; then
  echo "Independent persisted-state readback failed; inspect $PCM_TEST_OUT/reopen.log" >&2
  exit 1
fi
grep -E 'SE_MIGRATION_|RUSH_PCM_SE_MIGRATION' "$PCM_TEST_OUT/migration.log" | tail -12
grep -E 'PERSIST_REOPEN_|SUNPLUS_PCM_PERSIST_READBACK' "$PCM_TEST_OUT/reopen.log" | tail -8
echo "SUNPLUS_PCM_SAVED_ACCEPTANCE=PASS output=$PCM_TEST_OUT"
