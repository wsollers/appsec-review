# Freeciv walk 04 - `job_review_intake`

This record advances T-057. Walk terms, overlay and the expected-gaps list are in
[walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: stopped for a decision** (run `2026-11-11-0008`, overlay
`freeciv-b1b0768b/capacity-overlay.toml`). The output is correct against the target; one gap
cause, `file_too_large`, is not on the expected list.

## What the job did

Froze the configuration, repeated the model preflight, validated and fingerprinted the target.
Dispatch `d14806e4-6fae-4175-8f06-c5b0f8ca7fc0`, `attempt_0001`, `COMPLETED_WITH_GAPS`
(`next` wall time 2 min 56 s).

## Checks

- **A. Inputs.** No upstream in the contract; `upstream_handoffs` is `{}`. The frozen
  configuration layer hash is `c168f8c0...` for `appsec-review.toml`, profile `dev`.
- **B. Independent comparison** against `git -C targets/freeciv ls-files` and the files on disk:

  | Quantity | Job | Independent |
  | --- | ---: | ---: |
  | file paths examined | 6,726 | 6,726 tracked files |
  | excluded by configuration (`.gitignore` pattern) | 137 | 137 |
  | over the 2 MiB inventory bound | 38 | 38 (every tracked file >= 2,101,463 bytes; largest file under the bound is 2,083,972) |
  | fingerprinted text files | 3,493 | 3,493 (no NUL in the first 8,192 bytes) |
  | fingerprinted bytes | 119,195,017 | 119,195,017 |
  | binary content (artifact candidates) | 6,551 - 3,493 = 3,058 | 3,058 |
  | build descriptors matched / retained | 142 / 142 | not recounted here; walk 05 checks them |

  No symlinks, no untracked or ignored files on disk. None of the 137 excluded or 38 oversized
  files is source or a build descriptor.
- **C. Gaps.** 76 canonical records, one cause:

  | Cause | Records | Classification |
  | --- | ---: | --- |
  | `file_too_large` (38 files, each reported by `prepare_target.validate_target` and again by `publish_intake.publish_handoff`) | 76 | **not on the expected list: decision needed** |

  The 38 files: 16 Blender art files (`data/graphics/**/*.blend`), 13 translation catalogues
  (`translations/**/*.po`), 6 fonts (`data/themes/gui-sdl2|gui-sdl3/human/*.ttf`), `ChangeLog`,
  `ChangeLog-1.0-S3_0`, and one scenario savegame, `data/scenarios/europe_1900_WWI.sav`
  (9,960,830 bytes). The cause is the inventory bound of 2,097,152 bytes per file
  (`appsec_review.jobs.cataloging.Bounds`), not a failure. The effect: these files are outside
  the target fingerprint and the source inventory, so no later job reads them. `.git` is listed
  in the fingerprint's coverage notes as an excluded directory and is on the expected list.
- **D. Baseline.** Not saved; the job is checked, not accepted.

## The question

Is "data file over the configured 2 MiB inventory bound, when it is not source code or a build
descriptor" an expected gap? Recommendation: yes, with that condition, so that an oversized
source file or build descriptor still stops the walk. Cost: the fonts, art, translations,
changelogs and the one bundled scenario savegame are not inventoried or scanned.

## Not verified

The per-file SHA-256 values of the fingerprint were not recomputed; counts and total bytes were.
