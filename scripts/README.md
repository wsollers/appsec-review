# Scripts

Operator scripts for the review host. Every script exists as a bash script (`<name>.sh`, Linux and
WSL) and a PowerShell twin (`<name>.ps1`) with the same options (`--kebab-case` in bash,
`-PascalCase` in PowerShell). Run any of them with `--help` / `-Help` for the full option list.
Run them from any directory; they find the checkout themselves.

Platform: the review host runs Linux Docker in WSL. The stack and review twins take `-Wsl` (and
`-Distro`) to re-run the bash script inside WSL; without it they run `ops.py` with a local Python.
`compile-codeql-queries.ps1` always delegates to WSL on Windows. `render-report.ps1` runs natively.

## Dagster stack

Logic: `deploy/dagster/bin/ops.py`. Details:
[`docs/operations/operator-scripts.md`](../docs/operations/operator-scripts.md#stack).

| Script | Purpose |
| --- | --- |
| `stack-start.sh` / `.ps1` | Start (and if needed build) the Dagster stack, then check health, the Claude overlay and model connectivity. |
| `stack-stop.sh` / `.ps1` | Stop the containers, keeping volumes; refuses while a run is active unless `--force`; `--purge-volumes --yes` removes data. |
| `stack-restart.sh` / `.ps1` | Stop and start the stack, or recreate only the code location. |
| `stack-rebuild.sh` / `.ps1` | Build the image and recreate the stack with the Claude overlay. |
| `stack-status.sh` / `.ps1` | One-screen status: containers, health, compose files, image, active runs, disk. |
| `stack-logs.sh` / `.ps1` | Show one service's container logs. |

## Reviews

Logic: `deploy/dagster/bin/ops.py` and `review_run.py`. Details:
[`docs/operations/operator-scripts.md`](../docs/operations/operator-scripts.md#reviews).

| Script | Purpose |
| --- | --- |
| `review-start.sh` / `.ps1` | Launch `wave1_review` on the target the stack is built for; returns at once. |
| `review-watch.sh` / `.ps1` | Print one line per newly started job and the final status; exit 0/1 by status. |
| `review-status.sh` / `.ps1` | List recent runs and the active run's current steps. |
| `review-stop.sh` / `.ps1` | End the current review (every non-terminal run) with `SAFE_TERMINATE`; `--now` cancels at once. |
| `review-stop-id.sh` / `.ps1` | End one review by Dagster run id or application run id. |
| `render-report.sh` / `.ps1` | Render a finished run's report to PDF or single-page HTML (`--format pdf\|html`); output goes to `runs/reports/` by default. Details: [`docs/operations/report-rendering.md`](../docs/operations/report-rendering.md). |

## CodeQL

| Script | Purpose |
| --- | --- |
| `compile-codeql-queries.sh` / `.ps1` | Compile, one pack at a time, the CodeQL packs that are not precompiled (the graph-export packs registered with `warm = true` in `rules/registry.toml`) into the shared compile-cache volume review runs mount. Skips the image's standard query packs and the CERT pack, which ship precompiled `.qlx`. Options: `--language`, `--ram` (default 7000 MB), `--threads` (default 8), `--dry-run`, `--allow-concurrent`. Run it after a CodeQL image/release change or any graph-export QL change, before review runs. Wraps `containers/build.py query-packs --warm`. Details: [`docs/operations/codeql-analysis.md`](../docs/operations/codeql-analysis.md#compiling-codeql-queries). |

## Development

| Script | Purpose |
| --- | --- |
| `run-tests.sh` / `.ps1` | Run a named pytest suite with a unique base temp under `test/tmp/` and a log file; legacy suites report `known-failures.txt` entries as known. `--acceptance PROFILE` / `-Acceptance PROFILE` selects strict isolated acceptance (default one, maximum two workers), including dependency-ready producers, verified post-cleanup OUTPUT detachment, fresh immutable-union checks and private consumers; whole checkpoints/seals remain strict and blocked descendants never count as executed. No known-failure exemptions. The approved three-member exhaustive series qualified at `856300ca` in fresh sequential two-worker invocations (35 executions / 31 unique); monolithic `review-exhaustive` remains unqualified, not an umbrella alias or cap increase. Selection/results: [acceptance guide](../docs/operations/bounded-acceptance.md); CLI details: [`operator-scripts.md`](../docs/operations/operator-scripts.md#run-tests). |
| `clean-temp.sh` / `.ps1` | Remove disposable state under `test/tmp/` (dry run unless `--yes`). Details: [`operator-scripts.md`](../docs/operations/operator-scripts.md#clean-temp). |

## Support files

| File | Purpose |
| --- | --- |
| `lib/common.sh` | Sourced by the bash scripts: locates the checkout and a Python 3.11+ interpreter (`APPSEC_PYTHON`, the checkout's `.venv`, the main checkout's `.venv`, then `python3`) and runs `ops.py`. |
| `lib/common.ps1` | Dot-sourced by the PowerShell twins: finds the checkout (`APPSEC_REPO_ROOT`, the current directory, then the script location), translates paths for WSL and runs `ops.py` or the bash twin. |
| `known-failures.txt` | Pytest node ids that fail without this repository's changes; `run-tests` reports them as known. One `<node id> \| <reason>` per line. |