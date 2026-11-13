---
title: "Scripts"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Scripts

## Documentation generation

`scripts/generate-docs.sh` (or `.venv/bin/python scripts/generate-docs.py`) regenerates the
job inventory, guidance reference, job-page blocks and documentation indexes. `--check` reports
drift without writing; `--output-root test/tmp/<name>` writes an isolated reproduction.
The executive overview and its SVG are authored and are never generator outputs.

The generator loads the checked-in `dev` recipe through the typed loader, with no profile
overlay or host observations. Its in-memory unbound image sentinels only satisfy loader shape
validation; they are neither emitted nor usable as execution evidence. It never launches jobs,
tools or models, reads a target or run, or loads runtime skill text. Missing task bindings remain
explicit [T-147](../docs/TODO.md) gaps, not claims that a task has no tool or model.

Authored metadata uses one-line YAML scalars (JSON-quoted when needed) and JSON-style string
arrays. Required fields are `title`, `kind`, `subsystem`, `status` and `last reconciled`; `jobs`
is a sorted, unique array when relevant. Status is `current` or `historical`; task progress lives
in the TODO registry. The reconciliation value comes from `docs/docs-sync.json` and does not
advance merely because generated views changed. Generated Markdown carries its notice as the
first body line after frontmatter; generated JSON carries it on its first line.

Current prose identifiers are checked against the source inventory. Historical records and
explicitly marked historical passages retain retired names; the TODO registry is planning data.
A historical passage uses balanced `<!-- historical:begin -->` and `<!-- historical:end -->`
markers around the preserved text. Those markers do not exempt its links. Missing historical
archive citations are separately reported under [T-148](../docs/TODO.md); new broken links are
not accepted as archive exceptions.

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
| `stack-restart.sh` / `.ps1` | Stop and start the stack, or reload every Dagster image service (`--code-location-only`), keeping PostgreSQL. |
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
| `review-recover.sh` / `.ps1` | Recover one failed application run: the existing steps in order (dispatches terminal, reconcile the submission, verify worker stop, `plan-repair`, one confirmation, `admit-repair`, resume), stopping at the first refusal. Adds no authority; `--dry-run` prints the commands and runs none. |
| `render-report.sh` / `.ps1` | Render a finished run's review report to PDF or single-page HTML (`--format pdf\|html`), or with `--kind telemetry` (`-Kind telemetry`) its end-of-run telemetry report (`--format pdf\|tex`; a PDF goes to `runs/<id>/data/telemetry/report/`); other output goes to `runs/reports/` by default. Details: [`docs/operations/report-rendering.md`](../docs/operations/report-rendering.md), [`docs/operations/telemetry-report.md`](../docs/operations/telemetry-report.md). |

## CodeQL

| Script | Purpose |
| --- | --- |
| `run-readiness.sh` / `.ps1` | One-time preparation of a review host (T-057 Phase 0, `run-readiness.md` steps 1–5): preconditions (`default` Docker context, ext4 checkout, clean tree, OpenSSL 3, `.venv`), operator key + committed trust anchor + host trust directory, validate/build/smoke/report every image, host re-pin as its own commit, sign every pinned image, compile the CodeQL packs. Stops at the first failing step; `--from STEP` / `--only STEP` resume; `--dry-run` prints every command. Never pushes. On Windows always runs in WSL. Details: [`operator-scripts.md`](../docs/operations/operator-scripts.md#run-readiness). |
| `compile-codeql-queries.sh` / `.ps1` | Compile, one pack at a time, the CodeQL packs that are not precompiled (the graph-export packs registered with `warm = true` in `rules/registry.toml`) into the shared compile-cache volume review runs mount. Skips the image's standard query packs and the CERT pack, which ship precompiled `.qlx`. Options: `--language`, `--ram` (default 7000 MB), `--threads` (default 8), `--dry-run`, `--allow-concurrent`. Run it after a CodeQL image/release change or any graph-export QL change, before review runs. Wraps `containers/build.py query-packs --warm`. Details: [`docs/operations/codeql-analysis.md`](../docs/operations/codeql-analysis.md#compiling-codeql-queries). |

## Development

| Script | Purpose |
| --- | --- |
| `run-tests.sh` / `.ps1` | Run a named pytest suite with a unique base temp under `test/tmp/` and a log file, then print and save the fixed report (counts, elapsed, tests over 10 s, every FAILED/ERROR id verbatim with its `E` lines, log/junit/timings paths) and, with `--baseline FILE`, the differential whose new failures decide the exit code; legacy suites report `known-failures.txt` entries as known. `--coverage PACKAGE` / `-Coverage PACKAGE` adds branch coverage JSON for `appsec_review` or one dotted submodule, also in parallel; the report prints its path and line/branch totals without changing the exit verdict. Raw `--cov*` and `-p no:cacheprovider` remain refused. `--acceptance PROFILE` / `-Acceptance PROFILE` selects strict isolated acceptance (default one, maximum two workers), including dependency-ready producers, verified post-cleanup OUTPUT detachment, fresh immutable-union checks and private consumers; whole checkpoints/seals remain strict and blocked descendants never count as executed. No known-failure exemptions. The approved three-member exhaustive series qualified at `856300ca` in fresh sequential two-worker invocations (35 executions / 31 unique); monolithic `review-exhaustive` remains unqualified, not an umbrella alias or cap increase. Selection/results: [acceptance guide](../docs/operations/bounded-acceptance.md); CLI details: [`operator-scripts.md`](../docs/operations/operator-scripts.md#run-tests). |
| `clean-temp.sh` / `.ps1` | Remove disposable state under `test/tmp/` (dry run unless `--yes`). Details: [`operator-scripts.md`](../docs/operations/operator-scripts.md#clean-temp). |

## Support files

| File | Purpose |
| --- | --- |
| `lib/common.sh` | Sourced by the bash scripts: locates the checkout and a Python 3.11+ interpreter (`APPSEC_PYTHON`, the checkout's `.venv`, the main checkout's `.venv`, then `python3`) and runs `ops.py`. |
| `lib/common.ps1` | Dot-sourced by the PowerShell twins: finds the checkout (`APPSEC_REPO_ROOT`, the current directory, then the script location), translates paths for WSL and runs `ops.py` or the bash twin. |
| `known-failures.txt` | Pytest node ids that fail without this repository's changes; `run-tests` reports them as known. One `<node id> \| <reason>` per line. |