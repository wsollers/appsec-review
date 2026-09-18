# Config — Intake And Recovery

## Required Inputs

- target repo path
- engagement output directory
- business decision being supported
- target platform(s)
- known scope exclusions
- latest `job-status.md` if present

## Required Outputs

- recovered state summary
- artifact inventory
- scope assumptions
- next-lane recommendation
- **build-discovery note** (`build-discovery.md`) — required whenever this target does not already
  have a fresh, documented compile-database generation strategy on record from a prior run for this
  exact target. If a prior run's `build-discovery.md` is still current, say so explicitly in the
  state summary and cite it (run id + path) rather than silently omitting this output. Formalized
  2026-09-18 out of what had previously only existed as a one-off engagement-specific prompt
  (`appsec-review-process/initial-idsoftware-game-repo-compile-and-review.md`, Phases 2–3) — see
  `prompt.md` for the generalized steps.
