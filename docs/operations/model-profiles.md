# Model profiles: dev and prod

**Selection:** set `APPSEC_REVIEW_PROFILE=prod`, or use `--profile prod` on the stack and review
scripts (`-Profile prod` in PowerShell). The default is `dev`. Any other value is an error. Nothing
selects `prod` implicitly. The stack's profile is fixed when its containers are created, so switching
needs a stack restart.

```bash
# stack: recreate the containers under prod (a plain restart afterwards keeps prod)
scripts/stack-restart.sh --profile prod
scripts/stack-start.sh --profile prod              # first start, or after stack-stop
scripts/stack-rebuild.sh --profile prod            # rebuild the image, then recreate

# review: --profile prod means "I expect prod"; review-start refuses if the running stack differs
scripts/review-start.sh --profile prod --target appsec-multi-vuln

# direct CLI and library
APPSEC_REVIEW_PROFILE=prod appsec-review start --target targets/appsec-multi-vuln
appsec-review --profile prod start --target targets/appsec-multi-vuln
```

```powershell
scripts/stack-restart.ps1 -Profile prod
scripts/stack-start.ps1 -Profile prod
scripts/stack-rebuild.ps1 -Profile prod
scripts/review-start.ps1 -Profile prod -Target appsec-multi-vuln

$env:APPSEC_REVIEW_PROFILE = "prod"; appsec-review start --target targets/appsec-multi-vuln
```

`load_config(path, profile="prod")` does the same in code. `--profile dev` (`-Profile dev`) returns a
prod stack to dev the same way.

## What the profiles are

| Profile | Source | Models | Limits |
| --- | --- | --- | --- |
| `dev` (default) | `appsec-review.toml` exactly as checked in | Haiku 5.5 everywhere | the small limits in the file; cheap, for testing the pipeline |
| `prod` | `profiles/prod.toml` merged over `appsec-review.toml` | Sonnet 5.5, with Opus 5.5 for the independent verifier | large token limits and budgets for real reviews |

`profiles/prod.toml` is a configuration layer. It is deep-merged over the base file before
validation, so the normal typed validation checks the result (an unknown model profile for a role,
a missing key in a new profile and so on fail there). It is hashed as its own layer, listed in
`AppConfig.layers` after the base file and before the capacity overlay, and frozen with its whole
content in the run's `resolved.json` as `configuration_profile = {name, path, sha256, keys}`.
Every run records `configuration_profile`; a `dev` run records name `dev` with no file.

A profile file may set only the keys below. Anything else, a wrong type or an empty table is
rejected with a message that names the key.

| Table | Allowed keys |
| --- | --- |
| `jobs.<job>.settings.model` for `job_target_analysis_plan`, `job_project_build`, `job_post_build_security_assessment`, `job_dependency_intelligence`, `job_owasp_control_assessment` | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `timeout_seconds`, `retries` |
| `jobs.job_inference_security_review.settings.models.<profile>` (created or updated) | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `max_queries`, `max_turns`, `timeout_seconds` |
| `jobs.job_poc_generation.settings.models.<profile>` (existing profiles only) | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `max_queries`, `max_turns`, `timeout_seconds` |
| `jobs.job_inference_security_review.settings.roles.<role>` (the role must exist in the base) | `model_profile` |
| `jobs.job_inference_security_review.settings.budgets` | `max_model_turns`, `max_input_tokens`, `max_output_tokens`, `max_retrieval_queries`, `timeout_seconds` |
| `jobs.job_inference_security_review.settings.lanes` | `exploration_enabled` (Boolean), `exploration_reserve` (positive integer) |

Medium/low exploration is **off in both profiles**. Production's larger budget does not opt in.
Set `exploration_enabled = true` explicitly for the selected profile to admit up to
`exploration_reserve` otherwise-unadmitted medium/low packages within the existing lead allocation
and total budget. It does not admit informational leads or change unknown-severity handling.
See [review admission and rounds](inference-security-review.md#opt-in-mediumlow-exploration).

## The prod values

| Setting | Model | Reasoning | Max input | Max output | Timeout (s) |
| --- | --- | --- | --- | --- | --- |
| `job_target_analysis_plan` | `claude-sonnet-5-5` | high | 200000 | 64000 | 900 |
| `job_post_build_security_assessment` | `claude-sonnet-5-5` | high | 200000 | 32000 | 600 |
| `job_dependency_intelligence` | `claude-sonnet-5-5` | high | 200000 | 32000 | 600 |
| `job_owasp_control_assessment` | `claude-sonnet-5-5` | high | 200000 | 32000 | 600 |
| `job_project_build` | `claude-sonnet-5-5` | medium | 128000 | 16000 | 600 |
| inference review `models.default` | `claude-sonnet-5-5` | high | 200000 | 64000 | 1800 |
| inference review `models.strong` (new) | `claude-opus-5-5` | high | 200000 | 64000 | 2400 |
| PoC generation `models.default` | `claude-sonnet-5-5` | high | 200000 | 32000 | 600 |

`default` and `strong` also set `max_queries = 60` and `max_turns = 16`. The inference review budgets
become `max_model_turns = 60000`, `max_input_tokens = 600000000`, `max_output_tokens = 60000000`,
`max_retrieval_queries = 200000` and `timeout_seconds = 86400`.

## The verifier uses a different model

`profiles/prod.toml` binds `roles.independent_verifier.model_profile` to `strong`, so the verifier's
model (Opus 5.5) differs from every red cell's (Sonnet 5.5). That is what
`verification.require_distinct_model_for_ship_blocking` checks: under `prod` a ship-blocking
candidate can be published as `ship_blocking`, where under `dev` (every role on `default`) it stays
`ship_blocking_pending_distinct_verification`. `profiles/prod.toml` binds
`roles.adjudication_judge.model_profile` to `strong` as well, so the judge's model also differs from
every red cell's.

## Visibility and safety

- The active profile is printed as `profile: dev|prod` by `stack-start`, `stack-restart`,
  `stack-rebuild` and `review-start`, and shown by `stack-status`. `--profile prod` also prints a
  notice that prod uses the more capable models and larger token limits.
- `review-start --profile X` compares X with the running code-location's `APPSEC_REVIEW_PROFILE`
  (unset means `dev`) and refuses with exit 3, printing the `scripts/stack-restart --profile X` command,
  when they differ. Without `--profile` it reports what the stack runs.
- `stack-restart`, `stack-start` and `stack-rebuild` carry the running stack's profile over, like the
  target and overlay, so a plain restart never changes it.
- The model preflight (`job_review_intake`) and `job_model_connectivity` probe the models of the
  resolved configuration, so a `prod` run confirms Sonnet 5.5 and Opus 5.5 and an unavailable model
  blocks the run.
- `final-report.json` records `provenance.configuration_profile = {name, sha256}`.

## Fingerprints and the model contract

A profile changes behavior, so it is not excluded from any fingerprint. Cell fingerprints hash the
cell's provider, model, reasoning, token limits and timeout, and the semantic settings hash covers
the model profiles and budgets, so a `prod` run never reuses a `dev` cell and the reverse.

The model contract (`stepwise.py model-contract` and `system`) records the profile of the accepted
run in `model-contract.json` (`profile`; a contract without one was recorded under `dev`).
`system` prints the run's profile and reports `profile mismatch` as a model-contract input problem,
which fails the system verdict, when the run's profile differs from the contract's. Record a
separate contract for `prod`; do not compare a `prod` run with the `dev` contract.

## A work account whose model names differ

Edit `profiles/prod.toml` (the `model` values, and nothing else needs to change), then rerun:
`scripts/stack-rebuild --profile prod` copies the new file into the image (the Dockerfile copies
`profiles/` next to `appsec-review.toml`) and recreates the stack. The file hash is part of the
run's frozen configuration, so the edit is recorded. Do not use a model name that the account does not
list: the preflight reports it unavailable and blocks the run.
