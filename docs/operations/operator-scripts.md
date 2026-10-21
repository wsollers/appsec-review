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

## Conventions

- Run any script from any directory; the repository is found from the script's own path, and paths
  with spaces work.
- `--help` (`-Help`) lists the options. `--dry-run` (`-DryRun`) is offered wherever a script changes
  something: it prints what would happen, including the exact command lines, and changes nothing.
  A dry run still reports a refusal and exits 3 when the real run would be refused.
- Each script prints what it is about to do before it does it, and never prints secrets. Tool output
  that is shown (for example a failed model probe) has token-like strings replaced by `[redacted]`.
  Only three deployment settings are ever read from a container's environment
  (`APPSEC_REVIEW_TARGET`, `APPSEC_REVIEW_CONFIG_OVERLAY`, `APPSEC_REVIEW_MODEL_RECORDING`).
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
3. **Lifecycle only.** Stack changes call `deploy/dagster/bin/lifecycle.py`, which adds the Claude CLI
   overlay (`compose.claude.yaml` on WSL and Linux, `compose.windows.yaml` on Windows). The scripts
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
| `stack-start [--build] [--no-probe] [--dry-run] [--force] [--target T] [--overlay F] [--recording M]` | Build if asked (or if the image is missing), `lifecycle.py start`, then check health, the overlay and the model. |
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

`--target` takes a name under `targets/` or a container path (`/opt/app/targets/...`); `--overlay`
takes a capacity overlay file under `test/acceptance` (or `none`); `--recording` is `record`, `replay`
or `off`. They set `APPSEC_REVIEW_TARGET`, `APPSEC_REVIEW_CONFIG_OVERLAY` and
`APPSEC_REVIEW_MODEL_RECORDING` for the recreate (see
[`../processes/local-dagster-parity.md`](../processes/local-dagster-parity.md)). `replay` additionally
needs `APPSEC_REVIEW_MODEL_REPLAY_DIR`, which the compose file does not pass; the parity walk replays
locally instead.

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
--run-id <uuid>` executed in the webserver container, with `--tags` only when resuming. It is the
supported route because the Dagster daemon and run storage stay the single owner of the run, the
Dagster UUID is known before the run exists, and the application run id is read back from the run's
`appsec/application_run_id` tag. `review_run.py submit` does the same without tags or guards, so the
script adds the guards and the resume tag and reuses that helper's image-pin preflight.

The target, the capacity overlay and the recording mode are environment variables of the running
containers, fixed when they were created. `review-start` therefore checks the requested `--target`,
`--overlay` and `--recording` against the code-location container and refuses (exit 3) with the
`stack-restart` command that would change them; it never changes a running stack.

| Script | Purpose |
| --- | --- |
| `review-start [--target T] [--overlay F] [--recording M] [--run-id ID] [--id-wait S] [--dry-run] [--force]` | Launch `wave1_review` and return at once. Prints the Dagster run id, the application run id (read back for up to `--id-wait` seconds, default 60, else "pending") and the URL. `--run-id` resumes an existing application run (it must exist under `runs/`). Refuses when the stack is down, an image pin has moved, or a run is active (unless `--force`). |
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
