# Operator scripts

Small, guarded scripts in `scripts/` start and stop the local Dagster stack, start and end reviews,
clean disposable test state and run the tests. Every script exists twice with the same options: a
bash script (`scripts/<name>.sh`, Linux and WSL) and a PowerShell twin (`scripts/<name>.ps1`). The
logic lives in `deploy/dagster/bin/ops.py`, `ops_clean.py` and `ops_tests.py` (typed, unit-tested in
`tests/test_operator_scripts.py`); the scripts only locate the repository and a Python 3.11+
interpreter and pass their arguments on. The scripts add no pipeline behavior: the stack is still
built and started by `deploy/dagster/bin/lifecycle.py` and a review is still the `wave1_review`
Dagster job described in [`wave1-review.md`](wave1-review.md) and
[`../../deploy/dagster/README.md`](../../deploy/dagster/README.md).

Every script in `scripts/`, including `render-report` and `compile-codeql-queries` which are not
`ops.py` commands, is listed in [`../../scripts/README.md`](../../scripts/README.md).

For a first launch, see [review startup: features and flags](review-startup.md), which separates
required inputs, per-run options, stack settings and TOML-only feature gates.

## Conventions

- Run any script from any directory; the repository is found from the script's own path, and paths
  with spaces work.
- `--help` (`-Help`) lists the options. `--dry-run` (`-DryRun`) is offered wherever a script changes
  something: it prints what would happen, including the exact command lines, and changes nothing.
  A dry run still reports a refusal and exits 3 when the real run would be refused.
- Each script prints what it is about to do before it does it, and never prints secrets. Tool output
  that is shown (for example a failed model probe) has token-like strings replaced by `[redacted]`.
  Only four deployment settings are ever read from a container's environment
  (`APPSEC_REVIEW_TARGET`, `APPSEC_REVIEW_CONFIG_OVERLAY`, `APPSEC_REVIEW_MODEL_RECORDING`,
  `APPSEC_REVIEW_PROFILE`).
- Exit codes: `0` success, `1` the operation failed (or the final run status is not successful, or
  the stack is not healthy), `2` usage error, `3` refused by a safety rule, `4` nothing matched the
  id, target or file you named.
- Environment: `APPSEC_PYTHON` picks the interpreter (default: the checkout's `.venv`, then the main
  checkout's `.venv` when this is a git worktree, then `python3`); `APPSEC_DAGSTER_URL` or `--url`
  sets the GraphQL endpoint (default `http://127.0.0.1:3000/graphql`).
- PowerShell: options are `-PascalCase` (`--no-probe` is `-NoProbe`). Every twin also takes `-Wsl`
  and `-Distro` (default `Ubuntu-24.04`): with `-Wsl` the twin re-runs the bash script inside that
  WSL distribution, translating the repository path and any Windows path option. Use it when the
  stack runs in WSL, which is this host's normal deployment; a native Windows stack is run without
  `-Wsl`. (`-Wsl` is a switch with a separate `-Distro` value, not `-Wsl <distro>`.)

```powershell
.\scripts\stack-status.ps1 -Wsl
.\scripts\review-stop-id.ps1 -Wsl 2026-10-21-0007 -DryRun
```

- **PowerShell picks the checkout from where you start it.** The twins do not assume a location such as
  `F:\repos\appsec-review`. They look for the checkout in this order and print the choice on the first
  line (`[stack-status] repository: <path> (from current directory)`):
  1. `$env:APPSEC_REPO_ROOT`, if set (it must be a checkout: it needs `appsec-review.toml` and
     `deploy/dagster/bin/ops.py`, otherwise the script stops);
  2. the checkout that contains the current directory, found by walking up the parents like git does, so
     starting in any subdirectory of a checkout, or in one on a WSL path such as
     `\\wsl.localhost\Ubuntu-24.04\home\you\appsec-review`, acts on that checkout;
  3. the checkout the script file itself lives in, when the current directory is outside every checkout.
  With `-Wsl` the chosen checkout is translated to its WSL path and its own bash twin runs, and the
  distribution is taken from a `\\wsl.localhost\<distro>\` path unless `-Distro` is given. The stack's
  ownership rule (see Safety rules) is unchanged: start in the checkout that owns the stack.

```powershell
cd \\wsl.localhost\Ubuntu-24.04\home\you\appsec-review      # the checkout that owns the WSL stack
.\scripts\stack-status.ps1 -Wsl                               # repository: ... (from current directory)
$env:APPSEC_REPO_ROOT = 'D:\work\appsec-review'               # or name the checkout explicitly
```

## Safety rules

These enforce [`multi-session-coordination`](../../.claude/skills/multi-session-coordination/SKILL.md):
several sessions share one Docker daemon and one Dagster stack.

1. **Active-run guard.** A script that stops, restarts, rebuilds or recreates the stack, or that
   starts another review, first lists the Dagster runs. A run in any non-terminal state (`QUEUED`,
   `NOT_STARTED`, `MANAGED`, `STARTING`, `STARTED`, `CANCELING`) makes the script refuse with exit 3
   and name the runs. `--force` overrides it and prints a warning. If the stack is up but Dagster
   cannot be queried, the script refuses too (it cannot prove nothing is running); with the stack
   down there is nothing to protect. `stack-start` on a running stack is not guarded unless it
   would recreate containers (`--build`, or a changed `--target`/`--overlay`/`--recording`).
2. **Own stack only.** The stack scripts and `review-start` refuse (exit 3) when the running
   containers were created from another checkout's compose files, because `lifecycle.py` would
   recreate them from this checkout's mounts. Run the scripts from the checkout that owns the stack.
3. **Lifecycle only.** Stack changes call `deploy/dagster/bin/lifecycle.py`, which adds the provider
   overlay (`compose.copilot.yaml` for `copilot-dev` and `copilot-prod`; otherwise `compose.claude.yaml` on WSL and
   Linux or `compose.windows.yaml` on Windows). The scripts
   never run `docker compose` on `compose.yaml` alone. The only direct docker calls that change
   state are `docker exec ... dagster job launch` and, for `--purge-volumes`, removal of this
   project's own containers and volumes.
4. **No silent reverts.** Compose lets the shell override `.env`. `stack-restart`/`rebuild`/`start`
   carry the running code-location's non-empty target, overlay and recording values forward and say so,
   so a recreate never changes what a stack reviews. Change them only with the options below.
5. **Evidence.** `review-stop` and `review-stop-id` end runs with `recover_runs.py`, which writes
   `runs/metadata/dagster-recovery/<timestamp>.json`.

## Stack

| Script | Purpose |
| --- | --- |
| `stack-start [--build] [--no-probe] [--dry-run] [--force] [--target T] [--overlay F] [--recording M] [--profile dev\|prod\|copilot-dev\|copilot-prod]` | Build if asked (or if the image is missing), `lifecycle.py start`, then check health, the overlay and the model. |
| `stack-stop [--force] [--purge-volumes --yes] [--dry-run]` | `lifecycle.py stop`: containers stopped, volumes kept. |
| `stack-restart [--code-location-only] [--no-probe] [--force] [--dry-run] [--target T] ...` | Stop then start; `--code-location-only` uses `lifecycle.py reload`. |
| `stack-rebuild [--no-probe] [--force] [--dry-run] [--target T] ...` | `lifecycle.py build` then `start`, which recreates containers whose image changed. |
| `stack-status` | One screen: containers and health, compose files, image tag and age, deployment settings, active runs, last application run, Dagster URL, free disk of `runs/` and `test/tmp`. Exit 1 when a service is missing or unhealthy. |
| `stack-logs [service] [--tail N] [--follow]` | `docker logs` for one service, or every service without `--follow`. |

After starting, `stack-start`, `stack-restart` and `stack-rebuild` report:

- the state and health of `postgres`, `code-location`, `daemon` and `webserver`;
- whether the code-location's `com.docker.compose.project.config_files` label lists the overlay file
  (a stack created without it cannot reach the model);
- a one-word `claude -p` probe inside the code-location container (`--no-probe` skips it). If the probe
  reports an expired or missing OAuth token the script says how to refresh it: on WSL and Linux, run
  `claude -p "ok"` on the host, which refreshes the shared `~/.claude` token that the stack mounts
  read-only; on a native Windows stack, sign in again inside the container with
  `claude auth login` as in the deployment README.

For `copilot-dev` and `copilot-prod`, the probe instead checks the dedicated Copilot login and configured model catalog,
without inference. It does not call Claude or borrow the GitHub CLI account. Follow the
[separate-account setup](model-profiles.md#copilot-with-a-separate-github-identity) to sign in.

`--target` takes a name under `targets/` or a container path (`/opt/app/targets/...`); `--overlay`
takes a capacity overlay file under `test/acceptance` (or `none`); `--recording` is `record`, `replay`
or `off`; `--profile` is `dev` (default), `prod`, `copilot-dev`, or `copilot-prod`. They set `APPSEC_REVIEW_TARGET`,
`APPSEC_REVIEW_CONFIG_OVERLAY`, `APPSEC_REVIEW_MODEL_RECORDING` and `APPSEC_REVIEW_PROFILE` for the recreate (see
[`../processes/local-dagster-parity.md`](../processes/local-dagster-parity.md)). `replay` additionally
needs `APPSEC_REVIEW_MODEL_REPLAY_DIR`, which the compose file does not pass; the parity walk replays
locally instead.

The profile selects the models and limits (`dev`: Haiku and today's limits; `prod`: Sonnet 5.5, an Opus 5.5
verifier and larger limits; `copilot-dev`: Haiku through Copilot with unchanged dev limits;
`copilot-prod`: Sonnet 5.5 with an Opus 5.5 verifier and judge through Copilot, retaining all prod limits;
see [`model-profiles.md`](model-profiles.md)). The stack scripts set the container's default profile:
they print `profile: dev|prod|copilot-dev|copilot-prod` (and, for either production profile, a notice
that it uses the more capable models and larger token limits), carry the running value over on a plain
restart, and `stack-status` shows it. `review-start --profile X` and `--overlay F` choose the profile
and capacity overlay for that one run (see below).
PowerShell: `-Profile dev|prod|copilot-dev|copilot-prod` on the same four scripts.

### Per-run profile and overlay

`review-start --profile X --overlay F` (`-Profile X -Overlay F`) applies to that run only; the stack
is not restarted. Each value defaults first to what a resumed run (`--run-id`) recorded, then to the
container's `APPSEC_REVIEW_PROFILE` / `APPSEC_REVIEW_CONFIG_OVERLAY`. `review-start` prints each choice with
its source (`requested`, `recorded by run …` or `container default`) and launches with the Dagster tags
`appsec/profile=<name>` and `appsec/overlay=<container path>|none`. The code location resolves the run's
configuration from those tags with the same validation as the environment: a known profile, an overlay
under `test/acceptance`, and the same profile and overlay allowlists. The resolved choice is recorded
under `selection` (`profile`, `overlay`, `source`) in `runs/<run-id>/data/configuration/manifest.json`,
and a resumed run refuses a different selection from the one it was bound to. Runs launched without
the tags use the container environment, as before.

`review-start --compiler-target clang|msvc` (`-CompilerTarget clang|msvc`) also selects
the debug-symbol lane for that run, using the `appsec/compiler_target` tag. The default is
`clang`; a resumed run restores its frozen `selection.compiler_target` and refuses a
different explicit choice before submission. The compiler target participates in the
submission identity and resolved configuration hash. It is not a capacity-overlay key,
does not change the target checkout, and does not provision an MSVC build host.
See [build-bound debug symbols](../architecture/debug-symbol-indexing.md).

Some values stay fixed per container and are refused instead of silently ignored:

- The provider family. Copilot profiles need the `-copilot` image and compose overlay, so switching between
  `dev`/`prod` and `copilot-dev`/`copilot-prod` is refused (exit 3) with the `scripts/stack-restart --profile X`
  command. Within a family the switch is per run.
- `--target` and `--recording`. They must match the container, as before.
- Native execution. Its operator contract pins one configuration and resource budget, so any
  differing selection is refused.
- The `tree_sitter_ast` job. It builds its executor from the container configuration and refuses
  tags that select another.

`orchestration.dagster.pools.*` from an overlay applies to the selected run. The pools are tag
concurrency limits of the run's own multiprocess executor (the instance has no pool configuration),
so the run's executor is rebuilt with its values. Each run enforces its own limits; they are not
shared across concurrent runs.

**Resource budget guard.** Every run on the host shares `runs/metadata/resource-admission/leases.json`,
which admits against the smallest limits recorded by any lease. A run whose `review_policy.resources`
differ would silently clamp every concurrent run. When a run is active or the ledger holds leases,
`review-start` resolves the new run's budget and compares it with each active run's budget (from that
run's tags, defaulting to the container's selection) and with every recorded lease. It refuses
(exit 3) on any difference and names the conflicts. `--force` does not override this: wait for the
other runs or choose a matching selection. Capacity overlays can set `review_policy.resources.*`;
the guard also covers leases from other launchers.

`--purge-volumes` is separate and explicit. It prints the project's containers and volumes (the
PostgreSQL database and the Dagster storage, with every run's history), refuses without `--yes`, and
then removes only those. Nothing else is removed.

```bash
scripts/stack-start.sh --build
scripts/stack-restart.sh --target cpp-multivuln-v1 --overlay cpp-multivuln-v1/capacity-overlay.toml --recording record
scripts/stack-stop.sh --purge-volumes --yes --dry-run
scripts/stack-logs.sh code-location --tail 50 --follow
```

```powershell
.\scripts\stack-start.ps1 -Wsl -Build
.\scripts\stack-logs.ps1 -Wsl code-location -Tail 50
```

## Reviews

### Launch route

`review-start` uses the route the deployment README documents and `stepwise.py` and `review_run.py`
share: `dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j wave1_review
--run-id <uuid>` executed in the webserver container, with a submission-identity tag and an additional
application-run tag when resuming. It is the
supported route because the Dagster daemon and run storage stay the single owner of the run, the
Dagster UUID is known before the run exists, and the application run id is read back from the run's
`appsec/application_run_id` tag. `review_run.py submit` enters the same guarded implementation,
including the image-pin preflight; its `--run-id` supplies a Dagster UUID, whereas
`review-start --run-id` selects an existing application run to resume.

Both entrypoints serialize launch admission with a bounded kernel file lock under
`runs/metadata/dagster-submission/`. After preflight, `active.json` durably records the Dagster UUID,
source and target Git commits, configuration layer hashes (base, selected profile and overlay),
recording mode, Compose project, GraphQL endpoint, application resume ID and running code-location
image ID. Source tracked files must be unchanged and the target must be clean, including untracked
files. The target must map beneath this checkout's `targets/` mount. These are operator-input
identities, not proof that the image contains the checkout's implementation: installed-package
provenance and resolved runtime configuration still require the deployment preflight.

The intent is `UNCERTAIN` **before** invoking Dagster and becomes `SUBMITTED` only after the launch
command returns successfully. Failure, timeout, interruption or lost response retains the intent.
Another invocation, even with `--force`, cannot launch until explicit reconciliation. A changed
source, target, configuration or image reports an identity mismatch rather than replacing the
intent. A dry run writes nothing and still refuses an occupied intent. The lock coordinates these
two entrypoints in this checkout; it cannot prevent an operator from bypassing them with a raw
Dagster command or another deployment.

Inspect the exact recorded UUID in Dagster before explicitly acknowledging a terminal run:

```bash
python deploy/dagster/bin/review_run.py reconcile --run-id DAGSTER_UUID --url http://127.0.0.1:3000/graphql
```

Reconciliation requires the original endpoint, exact UUID, terminal `wave1_review` state and
matching `appsec/submission_identity` tag. Unknown runs, unavailable responses and identity
mismatches retain the reservation; do not delete the intent or invent a new UUID to work around
them. Reconciliation itself never submits a run. A subsequent separately authorized launch archives
the acknowledged intent as `<uuid>.json` before recording a new one; old UUIDs cannot be reused.
This acknowledgement does **not** certify descendant/container cleanup, release resource leases,
enable automatic retries, or establish first-error safety. First-error safety is a separate,
explicit launch policy described below; cleanup still requires independent confirmation.

### Opt-in first-error policy

After deployment and resource preflight, `review-start --stop-on-first-error` (PowerShell:
`-StopOnFirstError`) or `review_run.py submit --stop-on-first-error` freezes an execution-safety
envelope in the Dagster run configuration. It binds the Dagster UUID and the submission's
source, target and configuration identities. Its correlation hash and `dagster/max_retries=0`
are run tags. The deployed executor validates the envelope against the loaded configuration,
disables step retries, and starts one admission controller inside the existing run worker.
It does not start another scheduler or change profile files, models, budgets, or assurance.

The controller serializes cross-process admission through a private, same-UID Unix socket.
Its journal and ordered events are retained at
`runs/metadata/dagster-safety/<dagster-uuid>.json` and `.jsonl`. An admitted action is recorded
before its grant is returned. The first unexpected failure closes admission permanently;
queued threads, new model requests, retries, build repairs and further tool actions cannot
obtain another grant. Lost controller contact, failed journal writes and uncertain grant
responses fail closed. An existing journal is never adopted or restarted automatically.
Without the opt-in envelope, existing retry and gap behavior is unchanged.

Producer failures are intercepted before normal failure-to-gap conversion. Declared findings
exit codes, OSV's documented unsupported-input result, missing history, and cell authority or
budget dispositions retain their existing meaning. A producer exceeding a configured output
bound stops with `expected_policy_stop` recorded rather than being represented as a clean
completed result. Partial tool output, failed durations, cell attempts and exception evidence
remain in the run; failed outputs are not successful reusable checkpoints.

The controller requests termination of that exact Dagster run once. A termination request is
not proof that work died. Cleanup removes only tracked containers and requires explicit
absence, not just `Running=false`; dependent volumes are retained if container removal is
uncertain. Local CLI process groups are generation-checked before signaling. Unknown
descendants, incomplete SDK teardown, uncertain cancellation and quarantined resource leases
remain unresolved rather than being released or reported as cleaned up. Inspect the
controller journal, resource leases, Dagster state and actual descendants before recovery.
Partial execution receipts marked `cleanup: PENDING` deliberately do not certify cleanup.

This mode requires the matching installed implementation and Linux peer-authenticated Unix
sockets. Native-broker cancellation is not commissioned for this mode and is refused, never
replaced with ambient Docker execution. This software policy does not supply an aggregate
service/tool cgroup budget, commission an image builder, install dependencies, activate new
images, or make compilation ready. Those are separate deployment prerequisites.

The flag rejects application-run resume. A stopped policy journal or submission intent must
not be deleted to obtain a retry. Recovery requires separately approved compatible checkpoints
and a supported, explicitly linked new run segment; this option does not implement automatic
re-execution or authorize a second submission.

The target and recording mode are environment variables of the running containers, fixed when they
were created. `review-start` checks the requested `--target` and `--recording` against the
code-location container and refuses (exit 3) with the `stack-restart` command that would change
them; it never changes a running stack. Profile and capacity overlay can instead be selected
[per run](#per-run-profile-and-overlay), subject to the provider and resource-budget guards.

| Script | Purpose |
| --- | --- |
| `review-start [--target T] [--profile P] [--overlay F] [--recording M] [--run-id ID] [--stop-on-first-error] [--id-wait S] [--dry-run] [--force]` | Launch `wave1_review` and return at once. Prints the Dagster run id, the application run id (read back for up to `--id-wait` seconds, default 60, else "pending") and the URL. `--profile`/`--overlay` select this run's profile and capacity overlay ([per run](#per-run-profile-and-overlay)); `--target`/`--recording` must match the container. `--run-id` resumes an existing application run (it must exist under `runs/`) and cannot be combined with first-error mode. Refuses when the stack is down, an image pin has moved, a run is active (unless `--force`), or the selected resource budget differs from an active run's or lease's (even with `--force`). |
| `review-watch [--run ID] [--once] [--interval S]` | Poll the GraphQL API. Prints one line when each job starts (`[ 12.3 min] started codeql_analysis (14/33 jobs)`), one line per failed step, and a final line. Works for any run, whoever started it; `--run` takes a Dagster uuid or an application run id; without it the active run (else the latest). Exit 0 for `SUCCESS`, 1 for `FAILURE`/`CANCELED`. `--once` prints a snapshot and exits. |
| `review-status [--limit N]` | Recent runs with status, application run id, start and duration, and for each active run its started and finished jobs and current steps. |
| `review-stop [--now] [--yes] [--reason TEXT] [--dry-run]` | End the current review: lists every non-terminal run, then terminates them through `recover_runs.py`. Default policy `SAFE_TERMINATE`; `--now` uses `MARK_AS_CANCELED_IMMEDIATELY`, which marks runs canceled without waiting (their tool containers may keep running). Needs `--yes` when more than one run is affected. Nothing active is a no-op, exit 0. |
| `review-stop-id <id> [--now] [--yes] [--reason TEXT] [--dry-run]` | End one review. `<id>` is a Dagster run id (uuid) or an application run id such as `2026-10-21-0007`, resolved through the runs' tags. Refuses (3) a terminal run, answers 4 when nothing matches; needs `--yes` if several active Dagster runs share the application run. A queued run has no application tag yet, so use its Dagster id. |

```bash
scripts/review-start.sh --dry-run
scripts/review-start.sh
scripts/review-watch.sh --interval 30
scripts/review-status.sh --limit 5
scripts/review-stop-id.sh 2026-10-21-0007 --dry-run
```

```powershell
.\scripts\review-start.ps1 -Wsl
.\scripts\review-watch.ps1 -Wsl -Run 2026-10-21-0007 -Once
```

## clean-temp

`clean-temp` removes the disposable tree that `AGENTS.md` designates: entries of `test/tmp/` (pytest
base temp, the pytest cache at `test/tmp/.pytest_cache`, session scratch directories and the logs of
`run-tests`). It is a dry run unless `--yes` is given: it lists each entry with its size, then a
summary, and deletes nothing.

- `--older-than AGE` (default `2h`; `30m`, `1d`, or `0` for everything) keeps entries modified within
  that time, measured by the newest file inside the entry, so a concurrent session's fresh state
  survives.
- It deletes only direct children of the repository's real `test/tmp`. It refuses (exit 3) when
  `test/tmp` is a symlink or resolves outside the repository, skips any entry containing a symlink that
  points outside `test/tmp` and any top-level symlink (never followed or removed), skips entries that
  contain git-tracked files, and never touches `runs/`, `data/`, `targets/`, `old/`,
  `test/acceptance/` or anything outside `test/tmp`.
- `--docker` also lists, and never removes, containers named `appsec-review-build-*` (the build
  executor's disposable containers) and volumes named `appsec-codeql-*` (CodeQL's disposable database
  volumes). The Dagster project's own containers and volumes are never listed.

```bash
scripts/clean-temp.sh                       # dry run
scripts/clean-temp.sh --older-than 30m --yes
scripts/clean-temp.sh --docker
```

## run-tests

### Explicit acceptance profiles

`--acceptance <profile>` (`-Acceptance <profile>`) selects the separate bounded acceptance
driver, not one of the legacy suites below. For example:

```bash
scripts/run-tests.sh --acceptance quick --workers 1 --dry-run
scripts/run-tests.sh --acceptance graphs --workers 1
```

```powershell
.\scripts\run-tests.ps1 -Acceptance quick -Workers 1 -DryRun
.\scripts\run-tests.ps1 -Acceptance graphs -Workers 1
```

Acceptance requires the checkout's own virtual environment, always treats missing/skipped/failed
required coverage as failure, and writes its result/logs/fixture runs only under a unique
`test/tmp/acceptance/` root. `--workers` (`-Workers`) defaults to 1 and permits at most 2.
Staged review selects dependency-ready producer phases, frozen-input checkpoints and supervisor
seals before fresh private consumers. Failed producers leave descendants explicitly blocked,
not executed or successfully skipped. `review` has 13 core cases; `review-exhaustive` has 24
uncalibrated cases. Producer OUTPUT detachment is implemented after successful owned cleanup;
strict checkpoints/seals/copies remain. Optimized Windows review passed 13/13 and completes
its scoped Windows verification todo. Two two-worker quick warm runs passed 38/38; warm 3,
exhaustive selection and full portable process verification after the helper-budget fix
remain pending. Tagged workers use their existing 120-second exception internally; other
lifecycle helper cases retain 60 seconds. This is not a global cap increase or final green gate.
`--deadline` / `-Deadline` and `--case-deadline` / `-CaseDeadline` only lower profile caps.
Legacy suites, arbitrary pytest arguments, `--parallel` and `--background` cannot be combined
with acceptance; the known-failure exemption below does not apply.

See [bounded integration acceptance](bounded-acceptance.md) for profile selections, prerequisites,
strict collection and cleanup, output schemas, budgets, unimplemented optional profiles and the
shared-host caveat. The driver does not use a production Dagster endpoint or restart the stack.

### Legacy pytest suites

`run-tests` wraps pytest. It uses the checkout's `.venv` (`.venv/bin/python` or
`.venv\Scripts\python.exe`); in a worktree without one it falls back to the main checkout's venv and
sets `PYTHONPATH=src` so the worktree's code is the code under test. Each run gets
`--basetemp=test/tmp/tests-<suite>-<timestamp>` and a log at
`test/tmp/logs/tests-<suite>-<timestamp>.log`.

| Suite | Runs |
| --- | --- |
| `fast` (default) | all of `tests/` except `tests/live`, `tests/test_live_*.py` and `tests/integration`: offline, no Docker |
| `all-offline` | everything except the live tests (includes `tests/integration`) |
| `review` | `tests/review` |
| `orchestration` | `tests/orchestration`, the Dagster host/smoke/verify tests, the job runtime, launch and resume tests, and the operator-script tests |
| `docs` | documentation, repository hygiene, docs-sync and skill-separation tests |
| `graph` | `tests/graph` and the code-graph index job test |
| `live` | opt-in: `tests/live`, `tests/test_live_*.py`, `tests/integration`; needs Docker, the tool images, target checkouts and model access, and prints a warning |

Options: `--dry-run` prints the command and log path, `--background` starts detached and prints the
log path and how to follow it (`tail -f`), `--parallel` adds `-n auto` only when `pytest-xdist` is
installed (otherwise it warns and runs serially), `--strict` also fails on known failures. For an
arbitrary selection pass pytest arguments after `--` instead of a suite name.

`scripts/known-failures.txt` lists node ids that fail without any change of yours, one
`<node id> | <reason>` per line. The final summary reads `N failures, M known`, marks each known
failure, and exits 0 when only known failures remain (unless `--strict`). Remove a line when the
failure is fixed.

```bash
scripts/run-tests.sh                        # fast suite
scripts/run-tests.sh docs --background
scripts/run-tests.sh -- tests/test_config.py -k overlay
```

```powershell
.\scripts\run-tests.ps1 -Suite docs
.\scripts\run-tests.ps1 -Extra tests/test_config.py,-k,overlay
```

## Testing the scripts

`tests/test_operator_scripts.py` runs every script against fakes: a `docker` first on `PATH`, a
recording stand-in for `lifecycle.py`, and a local Dagster GraphQL server on a random port, all in a
sandbox copy of the repository under `test/tmp`. It checks `bash -n`, `shellcheck` and the PowerShell
parser when those tools exist, the help and error output, the arguments each script passes to
`lifecycle.py` and `docker exec`, the active-run guard, the stop policies and confirmations, and the
`clean-temp` and `run-tests` rules. The tests never touch the real stack.
