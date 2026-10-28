# Model profiles: dev, prod, copilot-dev and copilot-prod

**Selection:** set `APPSEC_REVIEW_PROFILE=prod`, or use `--profile prod` on the stack and review
scripts (`-Profile prod` in PowerShell). The default is `dev`; `copilot-dev` selects the separate
Copilot subscription transport with development limits. `copilot-prod` uses that transport with
production settings. Other values are errors. Nothing selects either production profile implicitly.
The stack's profile is the container default, set when its containers are created. `review-start
--profile` selects another profile of the same provider family for one run without a restart (see
[per-run profile and overlay](operator-scripts.md#per-run-profile-and-overlay)); switching between the
Claude and Copilot families needs a stack restart.

```bash
# stack: recreate the containers under prod (a plain restart afterwards keeps prod)
scripts/stack-restart.sh --profile prod
scripts/stack-start.sh --profile prod              # first start, or after stack-stop
scripts/stack-rebuild.sh --profile prod            # rebuild the image, then recreate

# review: --profile prod runs this review under prod, whatever the stack's default
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
| `copilot-dev` | `profiles/copilot-dev.toml` merged over `appsec-review.toml` | Haiku 5.5 through Copilot (`claude-haiku-5.5`) | exactly the dev reasoning settings, limits, roles and budgets |
| `copilot-prod` | `profiles/copilot-prod.toml` merged over `appsec-review.toml` | Sonnet 5.5 through Copilot (`claude-sonnet-5.5`), Opus 5.5 verifier and judge (`claude-opus-5.5`) | exactly the prod reasoning settings, limits, roles and budgets |

## Copilot production

`profiles/prod.toml` remains the authoritative production settings source. `copilot-prod.toml`
mirrors its overrides, changing only providers to `copilot-sdk` and model IDs to the exact dotted
Copilot catalog names. A regression test compares all resolved job settings with `prod`, including
disabled model settings, retries, query/turn limits, timeouts, budgets and role bindings. When
production settings change, update both files together. `dev` and `copilot-dev` retain their finite
package caps.

The independent verifier and adjudication judge use `strong` (`claude-opus-5.5`); primary workers
use `claude-sonnet-5.5`, preserving distinct-model verification. Inference-review ceilings remain
60,000 model turns, 600,000,000 input tokens, 60,000,000 output tokens, 200,000 retrieval queries
and 86,400 seconds. These are limits, not consumption targets.

Both production profiles set `budgets.budget_team_packages = "all"`. Every generated lead and hunt
package is eligible for a team launch: there is no package-count cutoff or fixed lane-share quota.
For example, queues of 485 lead and 114 hunt packages admit all 599, not 100 per lane. This does not
guarantee completion: token, turn, query, time, per-cell and concurrency safeguards remain in force,
and exhaustion still records explicit gaps. `dev` and `copilot-dev` keep the 200-package ceiling and
fair-share allocation. Existing runs retain their frozen settings; changing these profiles does not
alter historical runs.

Use the dedicated login below, verify the authenticated account and enabled exact model IDs,
and verify reasoning and transport limit support before launching. Catalog verification is not
an inference smoke test or proof of production-limit enforcement. There is no model substitution.
After all existing Dagster runs are terminal and image pins pass:

```bash
APPSEC_REVIEW_PROFILE=copilot-prod .venv/bin/python -c \
  "from appsec_review.inference.copilot_sdk import verify; print(verify())"
scripts/stack-rebuild.sh --profile copilot-prod
scripts/review-start.sh --profile copilot-prod --target appsec-multi-vuln
```

PowerShell uses `-Profile copilot-prod` on the corresponding scripts. Rebuilding is necessary
when the running image predates this profile. Both Copilot profiles use the same Copilot image
tag and overlay; changing profiles does not change the login or borrow Git credentials.

## Copilot with a separate GitHub identity

The optional `copilot-sdk` transport uses `github-copilot-sdk==1.0.25` and its checksum-verified
pinned runtime. Git and `gh` keep their existing account. Workers use a **separate** Copilot login;
they never use `gh auth token`, `GH_TOKEN`, `GITHUB_TOKEN`, or `COPILOT_GITHUB_TOKEN`. Those
ambient token variables are removed from the worker runtime environment.

From the checkout's own virtual environment on Linux/WSL:

```bash
python -m pip install -e '.[test,dagster,copilot]'
python -m copilot download-runtime
# Install Copilot CLI using https://docs.github.com/copilot/how-tos/copilot-cli/install-copilot-cli.
env -u GH_TOKEN -u GITHUB_TOKEN -u COPILOT_GITHUB_TOKEN \
  COPILOT_HOME="$HOME/.config/appsec-review/copilot" copilot login --device-code
# Authorize with the account whose Copilot subscription should run the jobs, not the Git account.
APPSEC_REVIEW_PROFILE=copilot-dev python -c \
  "from appsec_review.inference.copilot_sdk import verify; print(verify())"
```

`APPSEC_COPILOT_HOME` can select another dedicated login directory. It is a host path, never a
token. Keep it outside the repository. On Windows, set `COPILOT_HOME` to that same dedicated
directory for `copilot login`, with the three ambient token variables unset. The normal Git
credential helper and GitHub CLI configuration are not changed.

The check above authenticates and checks the model catalog, without starting a review or making
an inference request. Missing login, missing SDK/runtime, disabled models, unavailable exact model
IDs, or unsupported reasoning settings fail explicitly; there is no model or account fallback.
Copilot uses a dotted model version while Claude CLI uses `claude-haiku-5-5`; both profiles select
Haiku 5.5. Do not change to a different model merely to pass preflight.

Workers run in SDK `empty` mode with a temporary working directory, no tools, no MCP servers,
no skills, no extensions, no repository/user instruction discovery, and no file hooks or host Git
operations. Only application-supplied bounded prompts reach the model. Session-store persistence
and infinite-session compaction are disabled; timeout cancellation aborts the request and shuts
down the owned runtime. The transport records usage and verifies the returned model identity.

For Dagster, run bootstrap after the separate login, then select `copilot-dev` (or explicitly
`copilot-prod` for production) for every lifecycle
command (or save only `APPSEC_REVIEW_PROFILE=copilot-dev` in the ignored deployment `.env`):

```bash
python deploy/dagster/bin/bootstrap.py
APPSEC_REVIEW_PROFILE=copilot-dev python deploy/dagster/bin/lifecycle.py build
APPSEC_REVIEW_PROFILE=copilot-dev python deploy/dagster/bin/smoke.py --platform wsl --mode config
scripts/stack-start.sh --profile copilot-dev
```

The profile selects `compose.copilot.yaml` and the separate `<platform>-copilot` image tag. Only
the code location mounts the dedicated Copilot login, writable for token refresh; no credential
is copied into the image or repository. The SDK runtime is installed at image build time, never
downloaded during review inference. Claude authentication and Claude bind paths are not required.
As with every stack start, the daemon may run enabled schedules; do not start it during an
environment-only task that prohibits metadata refreshes.

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
| `jobs.job_owasp_control_assessment.settings.models.reviewer` (only this named profile) | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `timeout_seconds`, `retries` |
| `jobs.job_inference_security_review.settings.models.<profile>` (created or updated) | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `max_queries`, `max_turns`, `timeout_seconds` |
| `jobs.job_poc_generation.settings.models.<profile>` (existing profiles only) | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `max_queries`, `max_turns`, `timeout_seconds` |
| `jobs.job_inference_security_review.settings.roles.<role>` (the role must exist in the base) | `model_profile` |
| `jobs.job_inference_security_review.settings.budgets` | `budget_team_packages` (positive integer or `"all"`), `max_model_turns`, `max_input_tokens`, `max_output_tokens`, `max_retrieval_queries`, `timeout_seconds` |
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
| OWASP worker `model` | `claude-sonnet-5-5` | high | 200000 | 32000 | 600 |
| OWASP blinded `models.reviewer` | `claude-opus-5-5` | high | 200000 | 32000 | 600 |
| `job_project_build` | `claude-sonnet-5-5` | medium | 128000 | 16000 | 600 |
| inference review `models.default` | `claude-sonnet-5-5` | high | 200000 | 64000 | 1800 |
| inference review `models.strong` (new) | `claude-opus-5-5` | high | 200000 | 64000 | 2400 |
| PoC generation `models.default` | `claude-sonnet-5-5` | high | 200000 | 32000 | 600 |

OWASP remains disabled by its separate job-level `settings.enabled = false`; selecting a model
profile does not enable it. Base/dev worker and reviewer use `claude-haiku-5-5`; `copilot-dev`
selects `copilot-sdk`/`claude-haiku-5.5` for both. `copilot-prod` selects
`claude-sonnet-5.5` for the worker and `claude-opus-5.5` for the reviewer. Independent review means
a fresh blinded request over original evidence without the worker answer/transcript; model
distinctness alone is not proof. Qualification requires both selected profiles disabled explicitly,
not a provider overlay. See [OWASP operations](owasp-control-assessment.md).

`default` and `strong` also set `max_queries = 60` and `max_turns = 16`. The inference review budgets
become `budget_team_packages = "all"`, `max_model_turns = 60000`, `max_input_tokens = 600000000`, `max_output_tokens = 60000000`,
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

- The active profile is printed as `profile: dev|prod|copilot-dev|copilot-prod` by `stack-start`, `stack-restart`,
  `stack-rebuild` and `review-start`, and shown by `stack-status`. Both production profiles also print a
  notice that prod uses the more capable models and larger token limits.
- `review-start --profile X` runs that review under X (tag `appsec/profile=X`) when X is in the running
  code location's provider family. A Claude/Copilot family switch is refused with exit 3, printing the
  `scripts/stack-restart --profile X` command. Without `--profile` a resumed run keeps its recorded
  profile, and a new run uses the container's `APPSEC_REVIEW_PROFILE` (unset means `dev`). The choice
  and its source are printed and recorded in the run's configuration manifest.
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
