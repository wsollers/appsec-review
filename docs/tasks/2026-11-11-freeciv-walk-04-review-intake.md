# Freeciv walk 04 - `job_review_intake`

This record advances T-057. Walk terms, overlay, runs and the expected-gaps list are in
[walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: accepted** (run `2026-11-11-0009`, overlay `freeciv-b1b0768b/capacity-overlay.toml`,
corpus tag `freeciv-b1b0768b-v2`), after one stop and a user decision.

## What the job did

Froze the configuration, repeated the model preflight, validated and fingerprinted the target.
Accepted attempt: dispatch `d50d1037-ee20-4c4f-9cdc-7be8e987d433`, `attempt_0002`, `SUCCEEDED`,
29.3 s job time (`next` wall time 1 min 22 s). `attempt_0001` (dispatch `652ec6c9-...`) was
identical in content and was replayed because a later fix changed a module in this job's import
closure; the preserved-key comparison found 0 differences.

## The stop on run 0008 and the user's decision

On run `2026-11-11-0008` the job completed with 76 canonical gap records, one cause:
`file_too_large` for 38 files over the then hard-coded 2 MiB inventory bound, each reported by two
units of the job (T-095). The 38 were 16 `.blend`, 6 `.ttf`, 13 `.po`, `ChangeLog`,
`ChangeLog-1.0-S3_0` and one `.sav`; no source file or build descriptor. Not on the expected
list, so the walk stopped. The user decided (2026-11-11), instead of accepting the gap:

1. Non-code assets are excluded by type, as configuration, counted and named, never a gap: art
   sources, raster and icon images, video, audio, fonts, game saves. PDFs stay in ("They may just
   upload a doc instead of having the doc build").
2. The per-file bound is raised so translation catalogues are read.
3. Change logs stay in the inventory, for the source-history job (T-097, built separately).

Implemented in `85b3e061` and `740ea4f8`: `[[exclusions.asset_classes]]` (suffix match on the file
name, case-insensitive, compound suffixes; code-carrying suffixes and `.pdf` refused at load) and
the typed `[inventory] max_file_bytes = 12582912` (was 2,097,152), sized for the largest kept
file, `ChangeLog-1.0-S3_0` at 9,470,234 bytes. Tests: `tests/test_asset_exclusions.py`,
`tests/test_path_exclusions.py`. Documented in `docs/architecture/jobs-and-runtime.md`.

## Checks (run 0009)

- **A. Inputs.** No upstream in the contract; `upstream_handoffs` is `{}`.
- **B. Independent comparison** against `git -C targets/freeciv ls-files` and the files on disk,
  recomputed by a separate script from the resolved configuration's suffix lists and bound:

  | Quantity | Job | Independent |
  | --- | ---: | ---: |
  | file paths examined | 6,726 | 6,726 tracked files |
  | excluded by path pattern (`.gitignore`) | 137 | 137 |
  | excluded assets: `art-source` | 87 files, 163,019,325 bytes | same |
  | excluded assets: `raster-image` | 2,955 files, 25,509,268 bytes | same |
  | excluded assets: `audio` | 22 files, 1,472,394 bytes | same |
  | excluded assets: `font` | 8 files, 51,825,724 bytes | same |
  | excluded assets: `game-save` | 13 files, 11,745,970 bytes | same |
  | excluded assets: `video` | 0 | 0 |
  | over the 12 MiB bound | 0 | 0 |
  | fingerprinted text files / bytes | 3,496 / 161,577,309 | 3,496 / 161,577,309 |
  | binary content kept (artifact candidates) | 8 | 8 (7 `.ac.bz2`, 1 `.bmp.bz2`) |
  | build descriptors matched / retained | 142 / 142 | checked in walk 05 |

  137 + 3,085 + 0 + 8 + 3,496 = 6,726: every tracked file is accounted for. The 15 files the higher
  bound admits are the 13 `.po` catalogues and the two change logs (44 MB); nothing else in the
  target is over 2 MiB once assets are excluded. The target has no PDF.
- **C. Gaps.** 0 canonical gaps. `.git` appears in the fingerprint's coverage notes as an excluded
  directory (expected list); it is not a canonical gap record of this job.
- **D. Baseline.** `test/acceptance/freeciv-b1b0768b-v2/job_review_intake.json`.

## What the exclusions cost

3,085 files (254 MB) are outside the inventory: no job reads them. That includes the 13 bundled
scenario and savegame files and all image and sound data. Kept and named: 630 `.svg` files and
the 8 compressed files, because they can carry code or packed content.

## Not verified

The per-file SHA-256 values of the fingerprint were not recomputed; counts and bytes were. Whether
any excluded asset is referenced as a build input is not checked by the exclusion.
