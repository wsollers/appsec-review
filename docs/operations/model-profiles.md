---
title: "Runtime model profiles"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_dependency_intelligence", "job_inference_security_review", "job_model_connectivity", "job_owasp_control_assessment", "job_poc_generation", "job_post_build_security_assessment", "job_project_build", "job_review_intake", "job_target_analysis_plan"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Runtime model profiles

**Selection:** set `APPSEC_REVIEW_PROFILE=prod`, or use `--profile prod` on the stack and review
scripts (`-Profile prod` in PowerShell). The default is `dev`; `copilot-dev` retains its existing
model bindings with increased aggregate AI budgets. `copilot-dev-astra-6.2` and `copilot-dev-gemini`
are uniform-model Copilot comparison profiles with the same increased budgets. `copilot-prod` uses that transport with
production settings; `copilot-carbon-prod` selects Gemini 4 Carbon with its own production overrides.
These seven names are the accepted profiles. Nothing selects a production profile implicitly.
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
| `dev` (default) | `appsec-review.toml` exactly as checked in | Haiku 5.5 for primary workers; Sonnet 5.5 for the inference verifier and hunt planner, all through Claude CLI | development limits in the base file |
| `prod` | `profiles/prod.toml` merged over `appsec-review.toml` | `claude-fable-5-2` through Claude CLI for every configured model profile, including verification | large token limits and budgets; same-model verification remains qualified |
| `copilot-dev` | `profiles/copilot-dev.toml` merged over `appsec-review.toml` | Haiku 5.5 through Copilot for overridden profiles; inherited inference `planner` and `verifier` still use Claude CLI/Sonnet | 4× development aggregate AI budgets; not an entirely Copilot-resolved configuration |
| `copilot-dev-astra-6.2` | [`profiles/copilot-dev-astra-6.2.toml`](../../profiles/copilot-dev-astra-6.2.toml) merged over `appsec-review.toml` | `copilot-sdk` / `gpt-6.2-astra` / `high` for every configured model slot | 4× development aggregate AI budgets; base per-call and host limits |
| `copilot-dev-gemini` | [`profiles/copilot-dev-gemini.toml`](../../profiles/copilot-dev-gemini.toml) merged over `appsec-review.toml` | `copilot-sdk` / `gemini-4-carbon` / `high` for every configured model slot | 4× development aggregate AI budgets; base per-call and host limits |
| `copilot-prod` | `profiles/copilot-prod.toml` merged over `appsec-review.toml` | Copilot Sonnet 5.5 primary workers and Opus 5.5 `strong` verifier/judge; inherited inference `planner` and `verifier` still use Claude CLI/Sonnet | production review budgets; per-model overrides are not identical to `prod` |
| `copilot-carbon-prod` | `profiles/copilot-carbon-prod.toml` merged over `appsec-review.toml` | Gemini 4 Carbon through Copilot (`gemini-4-carbon`) at `high` reasoning across all jobs and roles | production budgets, exploration lane and active-claim cap, with output token caps sized within `gemini-4-carbon`'s 64k output limit |

## Reusable Copilot development comparisons

Select the exact profile name, including the dot in `copilot-dev-astra-6.2`. The first selected
smoke profile is Astra; future comparisons can select Gemini explicitly without changing the
binding files. Unattended jobs and CLI commands do not prompt for a model. There is no aliasing,
fallback or Claude routing in either new profile.

Both files override all configured model slots, not just inference discovery: target planning,
post-build assessment, dependency intelligence, OWASP worker and nested reviewer, project-build
model, inference `default`/`triage`/`planner`/`verifier`, PoC writer and remediation writer/reviewer.
The base has no optional `strong` profile; these comparisons do not introduce one or remap roles.
The actual resolved `configured_models` inventory is checked in offline regressions.

Only the following aggregate inference-review budgets increase, identically for `copilot-dev`,
`copilot-dev-astra-6.2` and `copilot-dev-gemini`:

| Budget | Unchanged `dev` | Three Copilot development profiles |
| --- | --- | --- |
| `max_input_tokens` | 480,000,000 | 1,920,000,000 |
| `max_output_tokens` | 48,000,000 | 192,000,000 |
| `max_model_turns` | 12,000 | 48,000 |
| `max_retrieval_queries` | 40,000 | 160,000 |
| `budget_team_packages` | 200 | 800 |
| `timeout_seconds` | 28,800 (8h) | 28,800 (8h), unchanged |

These are ceilings, not targets. Every per-call cap/deadline, host resource limit, pool, team
count, exploration setting, role assignment and assurance/citation policy stays at its base
development value. The unchanged 500-active-claim cap can still limit launches below 800:
485 lead plus 114 hunt packages allocate 386 lead and 114 hunt launches. Non-Copilot `dev`,
`prod` and both Copilot production profiles are unchanged. Old `copilot-dev` receives only the
budget changes; its inherited Claude slots remain the known [T-5270](../TODO.md) limitation.

Uniform-model comparison is **not independent-model confirmation**. Both new profiles preserve
`verification.require_distinct_model_for_ship_blocking = true`: the resolved settings warn,
otherwise confirmed ship-blocking candidates stay `ship_blocking_pending_distinct_verification`,
and a chain verifier requiring a distinct model cannot launch. Fresh blinded roles and resolving
citations are still required; they do not supply model distinctness.

For an explicitly authorized comparison, after the integration owner reloads signed mounted
sources with no active run and the dedicated account/catalog is ready:

```bash
# Reuse the existing verified Copilot tooling image; no image rebuild for profile changes.
scripts/stack-restart.sh --code-location-only --profile copilot-dev-astra-6.2
scripts/review-start.sh --profile copilot-dev-astra-6.2 --target appsec-review-smoke-cpp
# A later, separately authorized comparison on the same Copilot stack:
scripts/review-start.sh --profile copilot-dev-gemini --target appsec-review-smoke-cpp
```

PowerShell takes `-Profile copilot-dev-astra-6.2` or `-Profile copilot-dev-gemini` on the same
stack/review wrappers. The direct CLI takes `appsec-review --profile NAME ...`, and the library
takes `load_config(path, profile=NAME)`. A per-run switch within Copilot needs no image or login
change. Record a separate run/contract for each comparison: profile bytes and resolved settings
are hash-pinned and immutable for an existing run. Offline tests do not establish live catalog,
reasoning support, throughput or review quality.

## Copilot production

Each profile is merged over the base, not over another profile. `prod` and `copilot-prod` no
longer have full model/limit parity: `prod` selects Fable and overrides the hunt planner; the
older `copilot-dev`/`copilot-prod` overlays do not override the base `planner` or `verifier`.
The planner is enabled, and the development independent verifier uses that inherited profile;
`copilot-prod` binds its independent verifier to `strong` instead. The Copilot account/catalog check
refuses a configuration containing any non-Copilot model before contacting the catalog.
Inspect the resolved configuration
and arrange any required provider readiness explicitly; do not infer a fallback or silently
substitute a model. `copilot-carbon-prod` and the two new comparison profiles explicitly override
all these model profiles. All development profiles retain finite package caps.

In `copilot-prod`, the independent verifier and adjudication judge use `strong` (`claude-opus-5.5`); primary workers
use `claude-sonnet-5.5`, preserving distinct-model verification. Inference-review ceilings remain
60,000 model turns, 600,000,000 input tokens, 60,000,000 output tokens, 200,000 retrieval queries
and 86,400 seconds. These are limits, not consumption targets.

All three production profiles set `budgets.budget_team_packages = "all"` and
`rounds.max_active_claims = 1000`. There is no separate package-count budget, but package launches
are bounded by claim capacity: every launched package receives at least one claim slot.
When packages exceed 1,000, fair-share allocation across both lanes selects launches and records
explicit cutoffs for the rest. For example, queues of 485 lead and 114 hunt packages admit all
599 with nonzero allocations, not 100 per lane. This does not
guarantee completion: token, turn, query, time, per-cell and concurrency safeguards remain in force,
and exhaustion still records explicit gaps. `dev` keeps the 200-package ceiling; the three
Copilot development profiles have an 800-package ceiling and the unchanged 500-claim cap.
All use fair-share allocation. Existing runs retain their frozen settings; changing these profiles does not
alter historical runs.

Use the dedicated login below, verify the authenticated account and enabled exact model IDs,
and verify reasoning and transport limit support before launching. Catalog verification is not
an inference smoke test or proof of production-limit enforcement. There is no model substitution.
After all existing Dagster runs are terminal and image pins pass:

```bash
# This fully Copilot-bound production profile passes the all-provider guard:
APPSEC_REVIEW_PROFILE=copilot-carbon-prod .venv/bin/python -c \
  "from appsec_review.inference.copilot_sdk import verify; print(verify())"
scripts/stack-restart.sh --code-location-only --profile copilot-carbon-prod
scripts/review-start.sh --profile copilot-carbon-prod --target appsec-multi-vuln
```

PowerShell uses `-Profile copilot-carbon-prod` on the corresponding scripts. Rebuild only when the image's
dependencies, SDK/runtime or verifier need changing; profile TOML is mounted source, not an
image payload. All five Copilot profiles use the same Copilot image
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
APPSEC_REVIEW_PROFILE=copilot-dev-astra-6.2 python -c \
  "from appsec_review.inference.copilot_sdk import verify; print(verify())"
```

`APPSEC_COPILOT_HOME` can select another dedicated login directory. It is a host path, never a
token. Keep it outside the repository. On Windows, set `COPILOT_HOME` to that same dedicated
directory for `copilot login`, with the three ambient token variables unset. The normal Git
credential helper and GitHub CLI configuration are not changed.

The check above authenticates and checks the model catalog, without starting a review or making
an inference request. Missing login, missing SDK/runtime, disabled models, unavailable exact model
IDs fail explicitly; reasoning support must also be verified and is checked when sending a
model request. There is no model or account fallback.
Copilot's Haiku ID is dotted (`claude-haiku-5.5`); Claude CLI's is `claude-haiku-5-5`.
The inherited profiles described above are separate selections. Do not change to a different
model merely to pass preflight.

Workers run in SDK `empty` mode with a temporary working directory, no tools, no MCP servers,
no skills, no extensions, no repository/user instruction discovery, and no file hooks or host Git
operations. Only application-supplied bounded prompts reach the model. Session-store persistence
and infinite-session compaction are disabled; timeout cancellation aborts the request and shuts
down the owned runtime. The transport records usage and verifies the returned model identity.

For Dagster, run bootstrap after the separate login, then select `copilot-dev-astra-6.2` or
`copilot-dev-gemini` (or explicitly
`copilot-prod` / `copilot-carbon-prod` for production) for every lifecycle
command (or save only `APPSEC_REVIEW_PROFILE=copilot-dev-astra-6.2` in the ignored deployment `.env`):

```bash
python deploy/dagster/bin/bootstrap.py
APPSEC_REVIEW_PROFILE=copilot-dev-astra-6.2 python deploy/dagster/bin/lifecycle.py build
APPSEC_REVIEW_PROFILE=copilot-dev-astra-6.2 python deploy/dagster/bin/smoke.py --platform wsl --mode config
scripts/stack-start.sh --profile copilot-dev-astra-6.2
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
| `jobs.job_inference_security_review.settings.models.<profile>` (created or updated) | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `max_queries`, `max_turns`, `timeout_seconds`, `thinking_min_output_tokens` |
| `jobs.job_poc_generation.settings.models.<profile>` (existing profiles only) | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `max_queries`, `max_turns`, `timeout_seconds`, `thinking_min_output_tokens` |
| `jobs.job_remediation_planning.settings.writer`, `jobs.job_remediation_validation.settings.reviewer` | `provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `max_queries`, `max_turns`, `timeout_seconds`, `thinking_min_output_tokens` |
| `jobs.job_inference_security_review.settings.roles.<role>` (the role must exist in the base) | `model_profile` |
| `jobs.job_inference_security_review.settings.budgets` | `budget_team_packages` (positive integer or `"all"`), `max_model_turns`, `max_input_tokens`, `max_output_tokens`, `max_retrieval_queries`, `timeout_seconds` |
| `jobs.job_inference_security_review.settings.lanes` | `exploration_enabled` (Boolean), `exploration_reserve` (positive integer) |
| `jobs.job_inference_security_review.settings.teams` | `review_teams` (integer 1-64, capacity only) |
| `jobs.job_inference_security_review.settings.rounds` | `max_active_claims` (integer 1-100,000) |

Medium/low exploration is **on in all three production profiles**, and remains **off in `dev` and
all Copilot development profiles**. The production files explicitly set `exploration_enabled = true` and
`exploration_reserve = 20`: bounded otherwise-unadmitted medium/low packages alternate between
severities, in identity order within each severity, with unused slots going to the other population.
When both are plentiful this selects 10 medium and 10 low; launch-time cutoffs preserve the same
alternation (medium first for a single-slot tie). This is not exhaustive coverage of both severities.
Informational leads and unknown-severity handling do not change. The shipped base now limits
reviews to one round (`max_rounds = 1`, `stable_rounds_required = 1`), inherited by every profile;
the optional later-round machinery does not imply that a second round runs. The coverage settings use 7 production / 3 development concurrent
teams and raises production active-claim capacity to 1,000 (dev stays 500), with fair launch
cutoffs instead of zero-claim reviews. All other model, usage, and round limits are retained.
See the [resolved comparison and cutoff policy](inference-security-review.md#resolved-coverage-limits-and-cutoffs)
and [effective assignments](inference-security-review.md#effective-production-assignments-and-bounds)
for providers, models, personas, skills, pools, and residual gaps. Existing runs retain frozen
settings; offline verification does not imply a live production run.

## The prod values

These are configured model contracts, not proof that each worker is dispatched. In particular,
the current project-build units do not call the dormant image-repair inference helper; see
[worker dispatch boundaries](../architecture/worker-prompt-contracts.md#dispatch-inventory).
The central profile files and generated job declarations are authoritative for exact selections.
Remediation writer/reviewer profiles also have production overrides; their exact limits remain
in [`profiles/prod.toml`](../../profiles/prod.toml) and the corresponding Copilot profile, rather
than being inferred from this core-family summary.

| Setting | Model | Reasoning | Max input | Max output | Timeout (s) |
| --- | --- | --- | --- | --- | --- |
| `job_target_analysis_plan` | `claude-fable-5-2` | high | 200000 | 64000 | 900 |
| `job_post_build_security_assessment` | `claude-fable-5-2` | high | 200000 | 32000 | 600 |
| `job_dependency_intelligence` | `claude-fable-5-2` | high | 200000 | 32000 | 600 |
| OWASP worker `model` | `claude-fable-5-2` | high | 200000 | 32000 | 600 |
| OWASP blinded `models.reviewer` | `claude-fable-5-2` | high | 200000 | 32000 | 600 |
| `job_project_build` | `claude-fable-5-2` | medium | 128000 | 16000 | 600 |
| inference review `models.default` | `claude-fable-5-2` | high | 200000 | 64000 | 1800 |
| inference review `models.triage` | `claude-fable-5-2` | medium | 64000 | 16000 | 600 |
| inference review `models.planner` | `claude-fable-5-2` | high | 200000 | 32000 | 1200 |
| inference review `models.verifier` | `claude-fable-5-2` | high | 128000 | 32000 | 600 |
| inference review `models.strong` | `claude-fable-5-2` | high | 200000 | 64000 | 2400 |
| PoC generation `models.default` | `claude-fable-5-2` | high | 200000 | 32000 | 600 |

OWASP is enabled by default in all shipped profiles. Its separate job-level `settings.enabled = false`
opts out before a run is frozen; selecting a model profile does not override that gate.
Base/dev worker and reviewer use `claude-haiku-5-5`; `copilot-dev`
selects `copilot-sdk`/`claude-haiku-5.5` for both. `copilot-prod` selects
`claude-sonnet-5.5` for the worker and `claude-opus-5.5` for the reviewer. Independent review means
a fresh blinded request over original evidence without the worker answer/transcript; model
distinctness alone is not proof. Qualification requires both selected profiles disabled explicitly,
not a provider overlay. See [OWASP operations](owasp-control-assessment.md).

`default` and `strong` also set `max_queries = 60` and `max_turns = 16`. The inference review budgets
become `budget_team_packages = "all"`, `max_model_turns = 60000`, `max_input_tokens = 600000000`, `max_output_tokens = 60000000`,
`max_retrieval_queries = 200000` and `timeout_seconds = 86400`.

## Distinct-model verification depends on the profile

The distinct-model requirement remains enabled. `dev` binds the independent verifier to Sonnet
while primary workers use Haiku. `copilot-prod` binds the verifier/judge to Opus `strong`, distinct
from its Sonnet primary workers. In contrast, `prod` and `copilot-carbon-prod` bind `strong` but
select the same model as their primary workers. Both new Copilot comparison profiles keep the
base `verifier` assignment but select the same model across all slots. A different profile name or blinded request does
not supply model distinctness: otherwise ship-blocking candidates remain
`ship_blocking_pending_distinct_verification`, and a weakest-link chain verification requiring
distinctness cannot launch. No profile name alone certifies a finding.

## Visibility and safety

- The active profile is printed by `stack-start`, `stack-restart`, `stack-rebuild` and `review-start`,
  and shown by `stack-status`. Copilot development profiles print their aggregate-budget notice;
  the comparison notices name their exact model family. All three production profiles print a notice. The Carbon notice names
  Gemini; the current generic notice still says Sonnet/Opus even for `prod`. Read the resolved
  model declarations above rather than treating that notice as the actual model selection.
- `review-start --profile X` runs that review under X (tag `appsec/profile=X`) when X is in the running
  code location's provider family. A Claude/Copilot family switch is refused with exit 3, printing the
  `scripts/stack-restart --profile X` command. Without `--profile` a resumed run keeps its recorded
  profile, and a new run uses the container's `APPSEC_REVIEW_PROFILE` (unset means `dev`). The choice
  and its source are printed and recorded in the run's configuration manifest.
- `stack-restart`, `stack-start` and `stack-rebuild` carry the running stack's profile over, like the
  target and overlay, so a plain restart never changes it.
- The model preflight (`job_review_intake`) and `job_model_connectivity` probe the models of the
  resolved configuration, so a `prod` run requires its configured Fable model and an unavailable model
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

Edit the intended profile's exact model selections, checking every inherited profile, transport,
limit and account-supported ID. Profile files are part of the read-only mounted source,
not copied into the application image. After the active-run source freeze is released, use the
documented [source reload](image-pin-verification.md#deploying-changed-application-code) to re-sign
and recreate services, then create a new run with that profile. Rebuild only for dependency/tool/
verifier changes. The profile hash is frozen in the run; an unavailable model blocks preflight.
