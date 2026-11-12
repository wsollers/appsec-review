# Freeciv walk 03 - `job_target_acquisition`

This record advances T-057. Walk terms, overlay, runs and the expected-gaps list are in
[walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: accepted** (run `2026-11-11-0009`, overlay `freeciv-b1b0768b/capacity-overlay.toml`,
corpus tag `freeciv-b1b0768b-v2`).

> Update 2026-11-12: merging the change-log history feature changed the frozen configuration, so the
> walk restarted as run `2026-11-12-0001` with corpus tag `freeciv-b1b0768b-v3`. This job was run,
> verified with the same independent checks and accepted there with the same numbers as recorded
> below for `2026-11-11-0009`; `0009` and its `-v2` keys are retained and are not the baseline.

## What the job did

Nothing, correctly: the target is an explicit directory, so no acquisition is requested. First
dispatch `743d09df-39aa-43cc-8f2c-a399bdd0e806` (`attempt_0001`, 19.8 s job time, `next` wall time
1 min 14 s); replayed after each admitted repair with 0 preserved-key differences.

## Checks

- **A. Inputs.** No upstream in the contract; `upstream_handoffs` is `{}`.
- **B. Independent comparison.** The handoff records `status: NOT_REQUESTED` with a null
  `target_path`. After the job, `git -C targets/freeciv rev-parse HEAD` is still
  `b1b0768bfaca9b2fae68f9466defe1e80636e9fa` and `git status --short` is empty: the job did not
  pull, fetch or move the target.
- **C. Gaps.** 0 canonical gaps.
- **D. Baseline.** `test/acceptance/freeciv-b1b0768b-v2/job_target_acquisition.json`.

## Not verified

The acquisition path itself; this walk does not exercise it.
