# SPHE8202R `ap1.bin` analysis handoff

Status snapshot: 2026-10-01

This is the continuation/handoff note for the MIPS little-endian `ap1.bin` analysis in Analysis project `sphe8202r_decoder_p25d80` (`/modules_mipsle/ap1.bin`). It records both the established coverage baseline and the most recent audio/EQ findings so the next pass does not restart the same branch.

## Baseline

Last confirmed before the project session was released:

- total action nodes: **3828**;
- custom/meaningful names at that baseline: **117**;
- default/technical names: **3649**;
- forwarders: **60**;
- no external action nodes reported.

Two additional correct action boundaries were subsequently created during the current pass:

- `ApplyCurrentSevenBandEqPreset @ 0x806E89E4`;
- `HandleMusicPresetState @ 0x806E8A54`.

The final action-count/custom-name recount must be the first read-only step after reopening `ap1.bin`; do not infer a new exact total without that recount.

## Established analyzed clusters

The existing 117 custom names show substantial prior work in:

- USB host / SCSI / mass-storage / media-unit management;
- media source/session state;
- audio decoder/output routing;
- speaker/subwoofer/volume/mute control;
- S/PDIF and external-input state;
- audio-service register/command handling;
- audio preset/menu control.

Representative already-named actions include `DispatchAudioHardwareAction`, `StartConfiguredAudioPipeline`, `SetAudioDecoderState`, `ApplySpeakerConfiguration`, `SetMasterVolumeLevel`, `HandleAudioPresetMenuState`, `HandlePreviousAudioPresetMenuItem`, and `HandleNextAudioPresetMenuItem`.

## Seven-band EQ / music-preset cluster

This cluster is now strongly evidenced and should be continued before moving to a new subsystem.

### Preset bank

A table at `0x8070B37A` contains exactly **7 records x 7 bytes = 49 bytes**. Immediately after this bank is the UI format string `%d DB`.

Known record patterns include:

- neutral/flat record: `[13,13,13,13,13,13,13]`;
- other records form non-flat seven-value curves.

The code displays band values as `stored_value - 13` dB, proving encoded value `13` is `0 dB`.

UI/resource strings in the same firmware include `STANDARD`, `LIVELY`, `CONCERT`, `CLASSIC`, `ROCK`, `JAZZ`, `POP`, `MUSIC MODE`, `BASS MODE`, and `LIGHT MUSIC`.

Combined evidence supports classifying this as a **7-band EQ/music preset bank**, not a generic 7-byte configuration array.

### Fixed vs custom preset

- `DAT_80002B0D` is the current seven-band EQ preset index; the existing accessor `GetSevenBandEqPresetIndex` returns it directly.
- Preset index `7` selects a custom/user seven-byte curve from runtime RAM (`0x80002B10...`).
- Other preset indices select fixed records from the ROM bank at `0x8070B37A`.
- The fixed neutral/default curve is the all-13 record at `0x8070B388` (`0x8070B37A + 14`, record #2).

### Restored action boundaries

A previous analysis boundary around `0x806E89E4..0x806E8CF0` was incomplete. The pass reconstructed two real actions:

#### `ApplyCurrentSevenBandEqPreset @ 0x806E89E4`

Behavior:

1. load/apply EQ preset indexed by `DAT_80002B0D`;
2. program a related audio-service parameter from `DAT_80002B0C - 2`;
3. if preset index is `7`, copy the custom seven-byte RAM curve and apply it;
4. finish through the existing shared update path.

#### `HandleMusicPresetState @ 0x806E8A54`

Large music/audio-preset state worker. It:

- tracks menu page/state;
- reads/writes preset indices;
- applies fixed or custom seven-band curves;
- updates UI values/state;
- contains the custom-EQ editing substate;
- resets to the neutral curve in one branch.

### Existing forwarder at `0x806E8A48`

`thunk_FUN_806e9228 @ 0x806E8A48` initially looked like a bogus delay-slot boundary, but follow-up links proved it is a real shared-return/forwarder entry. It has an inbound call from another thunk and jumps into `FUN_806E9228`. **Do not delete it without a complete shared-return-flow repair.**

### Shared worker `FUN_806E9228`

Copies up to `0x80` bytes from a selected source into a work buffer and then calls one of two update/commit helpers. It is reached through more than one small thunk entry.

### Menu state

Evidence-backed roles:

- `DAT_80002B18` — top-level audio-preset menu page/index (`0..3` navigation seen in Prev/Next handlers);
- `DAT_80002B19` — menu substate (`0`, `1`, `2` observed; substate `2` enters custom-EQ editing behavior);
- `DAT_80002B22` — current custom-EQ band encoded value / UI selection; displayed as `value - 13` dB;
- `DAT_80002B0D` — current seven-band EQ preset index;
- `DAT_80002B0C` — adjacent encoded audio/EQ menu parameter used as `value - 2` by an accessor and service command wrapper.

These addresses currently live in runtime GP-state around `0x80002Bxx`; the existing `ap1.bin` project does not have a backing data block for that RAM window. Do not type these with `apply_data_type` until a narrow, justified runtime-state block is created.

### Relevant actions/helpers

Already named / restored:

- `HandleAudioPresetMenuState @ 0x806E781C`;
- `HandlePreviousAudioPresetMenuItem @ 0x806E8474`;
- `HandleNextAudioPresetMenuItem @ 0x806E86B4`;
- `ApplyCurrentSevenBandEqPreset @ 0x806E89E4`;
- `HandleMusicPresetState @ 0x806E8A54`;
- `GetSevenBandEqPresetIndex @ 0x806FFB78`;
- `InitializeAudioPresetMenu @ 0x806E7200`.

Still technically named but semantically understood:

- `FUN_806E8960` — loads a selected fixed seven-band EQ preset record into the working buffer; for preset indices 2..6 also triggers additional apply/update paths. Suggested name: `LoadSevenBandEqPreset`.
- `FUN_80702D64` — consumes a buffer and count <= 7; for each byte writes parameter indices `7..13` via a lower helper, then commits. Suggested name: `ProgramSevenBandEqValues` or similarly conservative.
- `FUN_806E8ED0` — passes a seven-byte buffer through the parameter-programming path and then calls the `0x0700` command-family wrapper. Suggested name should be chosen after the `0x0700` command meaning is pinned.
- `FUN_806E8CF0` — reset-to-neutral/default EQ path: sets preset state, copies the all-13 curve, then refreshes/updates. Suggested name: `ResetSevenBandEqToNeutral`.
- `FUN_806E735C` — formats/displays the current custom EQ band as `(encoded - 13) dB`; UI helper, not DSP logic.
- `FUN_806E7B5C`, `FUN_806E7C28`, `FUN_806E8664` — menu rendering/selection helpers; do not conflate them with EQ calculation.
- `FUN_806F983C` — setup/registration path that installs audio-preset menu callbacks through a generic callback registration helper.

## Important correction from this pass

Do not delete or automatically repair `thunk_FUN_806e9228 @ 0x806E8A48`. Initial inspection made it look like a stale delay-slot action, but explicit inbound links showed it is a real shared forwarder. This is exactly the kind of boundary where a speculative flow repair can destroy known-good state.

## Recommended next sequence

1. Reopen `/modules_mipsle/ap1.bin` and recount total/custom/default/forwarder action nodes.
2. Save the two newly created actions if the session has not already persisted them; confirm their names remain present.
3. Rename the semantically proven EQ helpers listed above, one mutation at a time (pre-tool filtering was intermittent on rename operations).
4. Materialize a **narrow** runtime RAM backing block around `0x80002B00..0x80002B3F` only after dry-run validation; then type/name the menu/EQ state fields above.
5. Continue through the custom-EQ editing branch and the `0x0700` command family until the service-side meaning is pinned.
6. After the EQ/music-preset cluster is coherent, move to the next audio-control cluster rather than spending time on cosmetic completeness scores.

## Progress reporting contract

For future analysis passes, report periodically using:

`ap1 progress ~N% | action nodes X/Y | custom named X | forwarders X | active module | concrete new findings | next target`

The overall percentage must state its denominator. Naming coverage and behavior/reverse coverage are different metrics and must not be silently merged.
