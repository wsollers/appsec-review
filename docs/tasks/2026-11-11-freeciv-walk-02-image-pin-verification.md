# Freeciv walk 02 - `job_image_pin_verification`

This record advances T-057. Walk terms, overlay and the expected-gaps list are in
[walk 01](2026-11-11-freeciv-walk-01-model-connectivity.md).

**Result: accepted** (run `2026-11-11-0008`, overlay `freeciv-b1b0768b/capacity-overlay.toml`).

## What the job did

Resolved the frozen image pins of the run's configuration and inspected each local image.
Dispatch `3a0991f0-4dc0-485f-a05e-a36128df1592`, `attempt_0001`, `SUCCEEDED`, job duration
37.5 s (`next` wall time 1 min 51 s).

## Checks

- **A. Inputs.** No upstream in the contract; `upstream_handoffs` is `{}`.
- **B. Independent comparison.** `image-pin-verification.json` lists 58 pins, all `matched`,
  over 47 distinct tags. For each distinct tag `docker image inspect --format '{{.Id}}'` on the
  host returned the pinned id: 47 of 47 agree, 0 mismatches. `deploy/dagster/host-pins.toml`
  holds 47 `sha256:` bindings.
- **C. Gaps.** 0 canonical gaps.
- **D. Baseline.** `test/acceptance/freeciv-b1b0768b-v1/job_image_pin_verification.json`.

## Not verified

That the images contain what their names say; the job verifies identity, not content. No image
was built, pulled or re-pinned.
