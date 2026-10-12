# Inference security review operations

Design authority: [`../architecture/inference-security-review.md`](../architecture/inference-security-review.md).
This page covers operator settings for `job_inference_security_review` (Dagster job
`inference_security_review`). All settings live in `appsec-review.toml` under
`[jobs.job_inference_security_review]`. Each run freezes them into
`runs/<run-id>/data/configuration/`.

## Model selection and upgrade

Models are configured as named profiles. Each role uses one profile, and a role without an entry
uses `default`:

```toml
[jobs.job_inference_security_review.settings.models.default]
provider = "claude-cli"          # claude-cli | anthropic-api
model = "claude-haiku-5-5"       # development default; upgrade for real reviews
reasoning = "high"
max_input_tokens = 32000
max_output_tokens = 8000
max_queries = 40                 # retrieval requests per cell
max_turns = 12                   # model turns per cell
timeout_seconds = 600            # per-cell deadline

[jobs.job_inference_security_review.settings.roles.independent_verifier]
model_profile = "default"
```

The checked-in default is the current Haiku model, which keeps development and fixture runs cheap.
To upgrade for a real review:

1. Change `model`, and `reasoning` if needed, in the `default` profile. To use a different model
   for some roles, add a profile such as `[...settings.models.review]` and point those roles at it
   with `model_profile = "review"`. A `default` profile is required, and a role that names a
   missing profile is rejected.
2. Revisit `max_input_tokens`, `max_output_tokens` and the job budgets
   (`[...settings.budgets]`), because larger models cost more per turn.
3. Start the run. `job_review_intake.model_preflight` confirms that the provider serves every
   configured model, including this job's profiles, before any review work. An unavailable model
   blocks the run.

**What a model change invalidates.** Provider, model and reasoning are inputs to every cell
fingerprint, so a run after a model change executes every review cell fresh and does not reuse
cells from earlier runs. Package assembly and the other upstream jobs are not affected. The run's
resolved-configuration hash also changes.

**Independence.** The blind verifier must be a different actor from the red and blue cells. It does
not need to be a different provider or model family; that requirement is open question 2 in the
design. Every finding package records `independence.provider_distinct`, so a run that uses one
model for every role is labelled as such.

## Capacity and local runs

`[...settings.teams].review_teams` (default 5) is the number of review teams, each 3 red, 2 blue
and 1 blind verifier, that may run at once on the host. To run a single team locally without
editing the checked-in file, supply a capacity overlay:

```toml
# local-capacity.toml
[jobs.job_inference_security_review.settings.teams]
review_teams = 1
```

Set `APPSEC_REVIEW_CONFIG_OVERLAY=local-capacity.toml`, or pass `overlay=` to `load_config`. The
overlay may set only `review_teams` and `orchestration.dagster.pools.*`; any other key is rejected.
It is recorded as its own hashed layer in the run's configuration manifest. Capacity is excluded
from cell fingerprints, so runs with different team counts reuse each other's cells and produce
identical canonical outputs.

## Outcomes

- Ordinary failures, such as provider errors, timeouts, invalid output, a failed team or an entire
  failed lane, become typed gaps. The handoff is then published with status `DEGRADED`.
  `review_incomplete = true` is set when the gap ratio exceeds `lanes.incomplete_gap_ratio`.
- Integrity failures block publication and leave the accepted pointer unchanged. These include a
  tampered manifest or shard, a broken ledger chain, a non-deterministic merge, or the application
  granting a forbidden capability.
- Re-executing a lane unit reuses every succeeded cell whose fingerprint still matches.
