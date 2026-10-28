# Starting an appsec review: features and flags

**For a full review, use `scripts/review-start` to launch Dagster's `wave1_review`.**
You do not need to enable each scanner or language on the command line: the catalog and analysis
plan select applicable work from the enabled jobs. Choose the target, model profile, and any
optional features before launch. The direct `appsec-review start` command is a smaller, linear
review route, not a replacement for every Dagster branch.

## Before the first launch

Complete the [repository setup](../../README.md#what-you-need) and
[Dagster deployment setup](../../deploy/dagster/README.md) first:

- Install Python 3.11+, the package in this checkout's own virtual environment, Docker and Compose.
  Bootstrap the deployment before using the stack scripts.
- Sign in to Claude for `dev`/`prod`, or configure the
  [separate Copilot login](model-profiles.md#copilot-with-a-separate-github-identity) for
  `copilot-dev`/`copilot-prod`. A GitHub CLI login is not the Copilot worker login.
- Place the target checkout under this repository's `targets/` directory. The guarded Dagster
  launcher requires unchanged tracked source in this appsec checkout and a clean Git target,
  including no untracked files. Leave both checkouts unchanged while a review uses them.
- Provision the enabled tool/build images and licensed CodeQL image, and verify their local
  immutable pins. The review does not build missing supplied images or silently accept moved pins;
  see [image-pin verification](image-pin-verification.md).
- Prepare the required [third-party metadata](third-party-data-sync.md). Review scanners do not
  refresh their databases during scanning.
- Confirm resource headroom and required build readiness. A Docker daemon alone does not commission
  the bounded image builder or restricted native execution. Required derived-image work needs an
  eligible prepared image or a commissioned compatible builder; see
  [performance and assurance](performance-assurance.md#scheduling-and-limits).

Use the checkout that owns the running stack. Do not start a second stack or use `--force` to
work around another session's active review.

## Full review: copyable launch sequence

Replace `your-app` with the directory name of your checkout under `targets/`. These examples
explicitly select **`prod`**, which uses production models and larger budgets; use `dev` for a
smaller pipeline trial. Neither production profile is selected automatically.

For a prepared WSL deployment, run from its owning checkout in PowerShell:

```powershell
# First start, or after the stack was stopped.
.\scripts\stack-start.ps1 -Wsl -Profile prod -Target your-app -Overlay none -Recording off
.\scripts\stack-status.ps1 -Wsl

# Inspect the choices and launch command without submitting, then submit once.
.\scripts\review-start.ps1 -Wsl -Target your-app -Profile prod -Overlay none -DryRun
.\scripts\review-start.ps1 -Wsl -Target your-app -Profile prod -Overlay none

# Replace DAGSTER_UUID with the id printed by review-start.
.\scripts\review-watch.ps1 -Wsl -Run DAGSTER_UUID
```

Omit `-Wsl` for a native Windows Compose deployment. Use `-Distro Ubuntu-24.04` to select the WSL
distribution explicitly; `-Wsl` itself is a switch, not a distribution argument.

The equivalent Linux/WSL shell sequence is:

```bash
scripts/stack-start.sh --profile prod --target your-app --overlay none --recording off
scripts/stack-status.sh
scripts/review-start.sh --target your-app --profile prod --overlay none --dry-run
scripts/review-start.sh --target your-app --profile prod --overlay none
scripts/review-watch.sh --run DAGSTER_UUID
```

If a stack is already running with a different target, recording mode, or provider family, use
`stack-restart` with the intended settings after its reviews are terminal. Use `stack-rebuild`
instead when the installed application, base TOML, or profile files changed: those files are baked
into the deployment image. A restart alone does not update them.

**On an already prepared stack with the correct defaults, no launch flags are required:**
`.\scripts\review-start.ps1 -Wsl` or `scripts/review-start.sh` is enough. Explicit target and profile
options make the intended review easier to verify. Launch returns after submission and a bounded
wait for the application id, not after review completion.

## Which startup flags to specify

These are **`review-start` script options**, not `appsec-review start` options.

| PowerShell | Shell | Default / when to specify |
| --- | --- | --- |
| `-Target your-app` | `--target your-app` | Uses the running container's target when omitted; the checked-in fallback is `appsec-multi-vuln`. Accepts a name under `targets/` or its container path. This checks the target; it does not switch the stack. A different target requires `stack-restart --target` first. |
| `-Profile prod` | `--profile prod` | New runs inherit the container's profile (`dev` if unset). Choose `prod` or `copilot-prod` explicitly for production models/budgets. A same-family profile change is per run; changing Claude/Copilot family requires a stack restart. |
| `-Overlay none` | `--overlay none` | New runs inherit the container's capacity overlay. `none` explicitly disables it for this run. A file must be under `test/acceptance`; it may change review-team count, Dagster pools, and `review_policy.resources.*`, not models, assurance, or feature gates. |
| `-Recording off` | `--recording off` | Inherits the container's model recording mode; unset means off. Choices: `off`, `record`, `replay`. Must match the container, so change it with `stack-restart --recording` first. Replay also needs a replay directory that the standard Compose deployment does not pass; use the [local parity procedure](../processes/local-dagster-parity.md), not this launch sequence, for replay. |
| `-StopOnFirstError` | `--stop-on-first-error` | **Off by default.** Fresh runs only. Freezes a no-retry safety policy that closes admission on the first unexpected failure. Requires matching deployed code and Linux peer-authenticated Unix sockets; native-broker cancellation is not commissioned for this mode. See [first-error policy](operator-scripts.md#opt-in-first-error-policy). |
| `-DryRun` | `--dry-run` | Prints choices and the launch command without submitting or writing an intent. Still checks preconditions and can refuse. |
| `-RunId 2026-10-21-0007` | `--run-id 2026-10-21-0007` | Resume an **existing application run**, not set the id of a fresh run. The run must exist under `runs/`; its recorded profile/overlay are the defaults and cannot be changed on resume. Cannot combine with first-error mode. |
| `-IdWait 60` | `--id-wait 60` | Wait up to 60 seconds for the application run id. `pending` means it has not been allocated yet, not that submission failed. Keep the printed Dagster UUID. |
| `-Url URL` | `--url URL` | GraphQL endpoint; defaults to `APPSEC_DAGSTER_URL`, otherwise `http://127.0.0.1:3000/graphql`. |
| `-Force` | `--force` | Overrides the active-run guard only. Not needed for normal launches; it cannot bypass stack ownership, submission identity, image pins, or conflicting active resource budgets. |
| `-Wsl`, `-Distro NAME` | Not applicable | PowerShell routing to the WSL stack; default distribution is `Ubuntu-24.04` unless inferred from the chosen WSL checkout path. |
| `-Help` | `--help` | Show the script's current option list. |

Profile choices:

| Profile | Provider and purpose |
| --- | --- |
| `dev` | Claude Haiku 5.5, smaller development budgets; default. |
| `prod` | Claude Sonnet 5.5 with Opus 5.5 verifier/judge and larger production budgets. |
| `copilot-dev` | Haiku 5.5 through the separately authenticated Copilot SDK, with dev limits. |
| `copilot-prod` | Sonnet 5.5 with Opus 5.5 verifier/judge through Copilot, with prod limits. |

Both production profiles admit all generated team packages rather than imposing the dev
200-package ceiling. Token, turn, query, time and concurrency limits still apply. Production
does **not** enable medium/low lead exploration. See [model profiles](model-profiles.md) for exact
limits and distinct-model verification behavior.

For an approved host capacity increase, select the checked-in
`prod-capacity-overlay.toml` instead of `none`. It sets three review teams, four I/O slots and
a scanner pool of four; it does not raise CPU or RAM. It is not implied by `--profile prod`.
Confirm the host and builder topology can support it first. A resource-budget mismatch with
an active run or recorded lease is refused even with `--force`.

## Features controlled in TOML, not launch flags

The checked-in defaults below come from [`appsec-review.toml`](../../appsec-review.toml).
Edit the existing setting in central configuration before creating a new run; do not add a
duplicate TOML table. Neither a prompt nor `--overlay` can enable these features. For Dagster,
commit configuration changes and rebuild the deployment before launch. Historical runs keep
their frozen configuration.

| Feature | Checked-in default / setting | What you need to do |
| --- | --- | --- |
| Applicable static scanners, builds, artifact analysis, CodeQL, code-graph/index creation, inference review and final publication | Included automatically when enabled and applicable. CodeQL has `jobs.job_codeql_analysis.settings.enabled = true`. | No per-tool launch flags. Supply the images, metadata and build prerequisites; missing or failed coverage remains a named gap, not a clean result. |
| Full assessment branches | Dagster includes CI configuration analysis, post-build security assessment, OWASP control assessment and security tagging. | Use `review-start` / `wave1_review`; these branches are absent from the direct CLI graph. |
| ASan/UBSan rebuild evidence | `jobs.job_sanitizer_build.settings.enabled = true` | No opt-in needed. Rebuilds accepted native units; does **not** execute produced binaries. See [sanitizer builds](sanitizer-build.md). |
| SVF points-to cross-checks | `jobs.job_svf_alias_analysis.settings.enabled = false` | Set `true` and provision the pinned SVF image and accepted C/C++ inputs. See [SVF analysis](svf-alias-analysis.md). |
| PoC unit-test generation | `jobs.job_poc_generation.settings.enabled = false` | Set `true` for automatic inclusion, or dispatch it manually on a finished run as shown below. This generates and compile-checks bounded test functions; it does **not** link or execute them. See [PoC generation](poc-generation.md). |
| Medium/low scanner-lead exploration | `jobs.job_inference_security_review.settings.lanes.exploration_enabled = false`; `exploration_reserve = 1` | Set `exploration_enabled = true` in the selected runtime profile or base configuration; choose the reserve within existing budgets. Does not admit informational leads or change unknown-severity handling. See [exploration admission](inference-security-review.md#opt-in-mediumlow-exploration). |
| Grype scanning | `tools.disable_grype = true` | Set `false` to restore normal applicability; still requires Syft SBOM and offline database prerequisites. See [static analysis](static-analysis.md). |
| Swift execution | `tools.enable_swift = false` | Set `true` only to remove the policy gate. This does not supply a Swift grammar or a supported macOS CodeQL executor; unsupported lanes remain gaps. See [Swift policy](swift-execution-policy.md). |
| Joern CPG analysis | `jobs.job_cpg_analysis.settings.enabled = false` | Deprecated, not required for the code-graph index. Leave disabled unless deliberately opting into that producer; see [C++ index jobs](cpp-index-jobs.md). |
| Test coverage and execution profiles | Ingestion jobs are in the review graph. | Supply supported reports through accepted build receipts. There is no startup flag that runs tests or profiles the target. See [coverage ingestion](test-coverage-ingestion.md) and [profile ingestion](profile-data.md). |
| Reduced repeated evidence verification | `review_policy.mode = "strict"` | `first_party_managed` is an explicit operator approval with project, target-root and custody requirements, not a speed flag. See [assurance policy](performance-assurance.md). |
| Pre-run third-party binary decompilation | No configured binaries by default. | Configure authorized binaries under `binary_decompilation.binaries`, then run `appsec-review binary-decompile` **before submission**. This is separate from the graph; see [binary decompilation](binary-decompilation.md). |

Optional manual PoC generation uses the application id and the run's matching configuration.
Republish the final report afterwards to include its accepted outcomes:

```powershell
appsec-review --profile prod run job_poc_generation --run-id 2026-10-21-0007 --upstream-from-run
appsec-review --profile prod run job_final_report_publication --run-id 2026-10-21-0007 --upstream-from-run
```

Restricted native execution is a separately commissioned deployment, not `-Wsl`, a review-start
feature switch, or permission to fall back to ambient Docker. Follow the
[native operator contract](../../deploy/dagster/native/README.md) for that route.

## Direct CLI alternative

From the repository root with this checkout's virtual environment active:

```powershell
appsec-review --profile prod start --target .\targets\your-app
```

`start` requires `--target` and allocates its own application run id. Global `--profile` and
`--config PATH-OR-FILE-URI` go **before** `start`; `--config` defaults to `appsec-review.toml`.
`APPSEC_REVIEW_PROFILE` supplies the profile when `--profile` is omitted, otherwise `dev` is used.
The direct CLI can load a capacity overlay through `APPSEC_REVIEW_CONFIG_OVERLAY`, but it has no
`start --overlay`, `--recording`, `--stop-on-first-error`, `--dry-run`, or `--run-id` flags.

Use the separate resume commands for an existing direct run:

```powershell
appsec-review --profile prod plan-resume --run-id 2026-10-21-0007 --target .\targets\your-app
appsec-review --profile prod resume --run-id 2026-10-21-0007 --target .\targets\your-app
```

Both accept `--force-from JOB_ID` to invalidate reuse from an enabled graph job onward.
`appsec-review run JOB_ID` dispatches one job; it does not start the full review.
See [the direct graph and its omissions](../../README.md#run-a-review).

## After submission

Keep both ids: the **Dagster UUID** identifies the orchestrated execution; the **application id**
(`YYYY-MM-DD-NNNN`) identifies evidence under `runs/`. `review-watch -Run` accepts either;
`appsec-review logs --run-id` takes the application id.

The launcher persists a submission intent under `runs/metadata/dagster-submission/`. A timeout
or lost response is **uncertain**, not permission to submit again. Inspect the recorded Dagster
UUID and follow [submission reconciliation](operator-scripts.md#launch-route) after the run is
terminal; do not delete the intent. First-error termination likewise does not prove all
descendants stopped or resource leases were released.

Review final outputs and named coverage gaps, not just the Dagster status. The accepted
`job_final_report_publication` handoff points to `final-report.json` and `final-report.md` under
`runs/<application-id>/data/jobs/job_final_report_publication/attempts/<attempt>/steps/`.
Use those accepted references rather than guessing the latest attempt; see
[final publication](final-report.md) and the separate [HTML/PDF renderer](report-rendering.md).
