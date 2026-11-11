# Freeciv walk 03 - `job_target_acquisition`

This record advances T-057. Walk terms, overlay and the expected-gaps list are in
[walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: accepted** (run `2026-11-11-0008`, overlay `freeciv-b1b0768b/capacity-overlay.toml`).

## What the job did

Nothing, correctly: the target is an explicit directory, so no acquisition is requested.
Dispatch `3b670d2c-a30a-440e-96c1-860616957b1d`, `attempt_0001`, `SUCCEEDED`, job duration
30.9 s (`next` wall time 1 min 16 s).

## Checks

- **A. Inputs.** No upstream in the contract; `upstream_handoffs` is `{}`.
- **B. Independent comparison.** The plan records `requested: false`; the handoff records
  `status: NOT_REQUESTED` with null `system_id`, `target_path` and `tree_sha256`. After the job,
  `git -C targets/freeciv rev-parse HEAD` is still `b1b0768bfaca9b2fae68f9466defe1e80636e9fa`,
  `git status --short` is empty, and the newest reflog entry is the user's checkout at 16:43,
  before the walk: the job did not pull, fetch or move the target.
- **C. Gaps.** 0 canonical gaps.
- **D. Baseline.** `test/acceptance/freeciv-b1b0768b-v1/job_target_acquisition.json`.

## Not verified

The acquisition path itself; this walk does not exercise it.
