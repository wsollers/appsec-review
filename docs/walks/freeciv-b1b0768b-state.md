# Walk state: Freeciv at `b1b0768b`

The current position of the walk whose terms are in [freeciv-b1b0768b.md](freeciv-b1b0768b.md).
The walker rewrites this file at every acceptance, stop and restart
([walk charter](../processes/walk-charter.md), section 7). A fresh session compares it with the
host before acting.

**As of:** 2026-11-12 about 07:40 UTC, `main` and `origin/main` at `b21c90b0` (record 06 and this file are committed on top, unpushed). Written by the walker after job 6 was run and stopped.

| Item | Value |
| --- | --- |
| Run | `2026-11-12-0001` (earlier runs `2026-11-11-0007` to `-0009` are retained and are not the baseline) |
| Corpus namespace | `freeciv-b1b0768b-v3`; target tag `freeciv-b1b0768b-v1` |
| Overlay | `freeciv-b1b0768b/capacity-overlay.toml` (`cpu = 20`, `io_slots = 4`) |
| Accepted | jobs 1 to 5: `job_model_connectivity`, `job_image_pin_verification`, `job_target_acquisition`, `job_review_intake` (0 gaps each), `job_target_catalog` (28 gap records, 5 causes, all on the expected list). Records 01 to 05 |
| Accepted attempts | job 1 `attempt_0004`, jobs 2 to 4 `attempt_0003`, job 5 `attempt_0003`; every replay compared equal to its preserved key (0 differences) |
| Job in hand | 6, `job_source_history_analysis`: **rerun after the anchor fix, stopped for decisions, not accepted**. Dagster run `d2474825-8fa7-4183-a77a-48335dcf6ffc`, `attempt_0002`, `COMPLETED_WITH_GAPS`, check passed; history binds to the pin (exact, 0 divergent). First attempt `attempt_0001` (`ad630bf6...`) is superseded. Record 06 |
| Stack | idle, five services healthy, target `/opt/app/targets/freeciv`, profile `dev`, recording `record` |
| Target | `b1b0768bfaca9b2fae68f9466defe1e80636e9fa`, status clean |

## How to continue

```sh
.venv/bin/python deploy/dagster/bin/stepwise.py next --app-run 2026-11-12-0001
# four checks, record docs/tasks/2026-11-11-freeciv-walk-06-source-history-analysis.md, then
.venv/bin/python deploy/dagster/bin/stepwise.py accept --app-run 2026-11-12-0001 \
  --job job_source_history_analysis --tag freeciv-b1b0768b-v3 --target-tag freeciv-b1b0768b-v1
```

Pass the run id explicitly on every command. Run ids roll to the UTC date; one script of this
walk addressed the previous day's run after midnight (it wrote nothing; see record 05).

## Job 6 as found (record 06)

- Several gap causes are not on the expected list: `untracked_path`, `working_tree_divergent`,
  `head_differs_from_mainline`, `timestamp_anomaly`, `fix_on_fix_undetermined`, parse and symbol
  gaps, change-log gaps (0 of 24,204 paths bound), deployment and pull-request timing.
- `bind_snapshot` reports 1,429 divergent and 189 untracked files on a clean target; blob ids it
  records differ from git at the pin (example `ci.yml`: `34cbd111...` against `b4137ec5...`), which
  suggests the history is bound to a revision other than the pin. The clone holds branches and
  58,798 commits against 31,479 from the pin. Not established; see record 06.
- To continue after the decisions: re-launching job 6 is `stepwise.py next --app-run
  2026-11-12-0001 --relaunch` only after a fix and the repair path (charter sections 6 and 10).
  The accept command is unchanged. Run the WSL command itself as the background task; a `&` inside
  `bash -lc` dies with the shell.

## Host notes a fresh session needs

- The Claude login mounted into the stack expires. If a model probe or `job_model_connectivity`
  reports `401 OAuth access token has expired`, refresh it once on the host with
  `$(grep APPSEC_CLAUDE_BINARY deploy/dagster/.env | cut -d= -f2) -p "reply ok" --model claude-haiku-5-5`
  and re-run the job. It expired once during this walk (2026-11-12 01:38 EST).
- A replay through the catalog costs about 8 minutes (jobs 1 to 4 about 75 s each, the catalog
  about 110 s).
- Scratch worktrees used for comparisons: `~/projects/appsec-review-merge-check` and
  `~/projects/appsec-review-merge-check-fx` (detached, disposable); the walk branch is
  `freeciv-walk` in `~/projects/appsec-review-freeciv-walk`.
- Accepted key directories `test/acceptance/freeciv-b1b0768b-v1`, `-v2`, `-v3` and
  `test/acceptance/AcceptanceTest/` are untracked in the main checkout. Only `-v3` is this walk's
  baseline. None is committed; whether to commit `-v3` is the user's call.

## Waiting on the user

- Record 06, decision 1 is answered: the anchor bug was fixed and pushed (`38777f90`, origin/main
  `d901bac4`) and job 6 was rerun on it (`attempt_0002`).
- Record 06, rerun section: which of the remaining job 6 gap causes join the expected list
  (symbol and parse gaps, `line_history_file_too_large`, change-log gaps, `timestamp_anomaly:1`, the
  two timing gaps). Accept with `stepwise.py accept` (command above) after that decision.
- Host trap: a bare `lifecycle.py reload` resets target and overlay to the `.env` defaults; follow it
  with `scripts/stack-restart.sh --code-location-only --target freeciv --overlay
  freeciv-b1b0768b/capacity-overlay.toml`, and a changed implementation needs `recover`,
  `plan-repair`, `admit-repair` before `next --relaunch` (record 06).
- Blindness note in record 06: one commit subject of the target clone was seen incidentally.

## In flight

- Unmerged local branches held until after the walk: `wave3-composer`, `wave2-osv`.
- `wave3-fixtures` (`6055d078`) was declined: on current `main` it adds two collection errors and
  its fixtures append release ids that `main` now declares. It needs rebasing by its author.
- Design session `dfd-threat-model` (branch of that name, not merged) holds T-107 and T-108.
- The nightly data sync is stopped and the feeds are stale (T-106); restarting it is the user's.
