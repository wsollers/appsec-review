# Freeciv walk 02 - `job_image_pin_verification`

This record advances T-057. Walk terms, overlay, runs and the expected-gaps list are in
[walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: accepted** (run `2026-11-11-0009`, overlay `freeciv-b1b0768b/capacity-overlay.toml`,
corpus tag `freeciv-b1b0768b-v2`).

> Update 2026-11-12: merging the change-log history feature changed the frozen configuration, so the
> walk restarted as run `2026-11-12-0001` with corpus tag `freeciv-b1b0768b-v3`. This job was run,
> verified with the same independent checks and accepted there with the same numbers as recorded
> below for `2026-11-11-0009`; `0009` and its `-v2` keys are retained and are not the baseline.

## What the job did

Resolved the frozen image pins of the run's configuration and inspected each local image. First
dispatch `4d157b38-a5c5-45fe-ac4f-fbb002b15153` (`attempt_0001`, 20.8 s job time, `next` wall time
1 min 17 s); replayed after each admitted repair with 0 preserved-key differences.

## Checks

- **A. Inputs.** No upstream in the contract; `upstream_handoffs` is `{}`.
- **B. Independent comparison.** `image-pin-verification.json` lists 58 pins, all `matched`,
  over 47 distinct tags. For each distinct tag `docker image inspect --format '{{.Id}}'` on the
  host returned the pinned id: 47 of 47 agree, 0 mismatches. `deploy/dagster/host-pins.toml`
  holds 47 `sha256:` bindings.
- **C. Gaps.** 0 canonical gaps.
- **D. Baseline.** `test/acceptance/freeciv-b1b0768b-v2/job_image_pin_verification.json`.

## Not verified

That the images contain what their names say; the job verifies identity, not content. No image
was built, pulled or re-pinned.
