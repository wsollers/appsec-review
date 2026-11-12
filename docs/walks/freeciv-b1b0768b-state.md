# Walk state: Freeciv at `b1b0768b`

The current position of the walk whose terms are in [freeciv-b1b0768b.md](freeciv-b1b0768b.md).
The walker rewrites this file at every acceptance, stop and restart
([walk charter](../processes/walk-charter.md), section 7). A fresh session compares it with the
host before acting.

**As of:** 2026-11-12 about 11:55 UTC, `origin/main` at `d901bac4`; local `main` is ahead with the walk documents (unpushed). Written by the walker after job 6 was accepted.

| Item | Value |
| --- | --- |
| Run | `2026-11-12-0001` (earlier runs `2026-11-11-0007` to `-0009` are retained and are not the baseline) |
| Corpus namespace | `freeciv-b1b0768b-v3`; target tag `freeciv-b1b0768b-v1` |
| Overlay | `freeciv-b1b0768b/capacity-overlay.toml` (`cpu = 20`, `io_slots = 4`) |
| Accepted | jobs 1 to 6: `job_model_connectivity`, `job_image_pin_verification`, `job_target_acquisition`, `job_review_intake` (0 gaps each), `job_target_catalog` (28 gap records, 5 causes, all on the expected list), `job_source_history_analysis` (28 unique gaps, all on the expected list after the 2026-11-12 decisions). Records 01 to 06 |
| Accepted attempts | job 1 `attempt_0004`, jobs 2 to 4 `attempt_0003`, job 5 `attempt_0003`, job 6 `attempt_0002`; every replay of jobs 1 to 5 compared equal to its preserved key (0 differences); job 6 had no replay |
| Job 6 | `job_source_history_analysis`: **accepted** 2026-11-12 on `attempt_0002` (Dagster run `d2474825-8fa7-4183-a77a-48335dcf6ffc`, `COMPLETED_WITH_GAPS`, check passed; history binds to the pin, exact, 0 divergent). Baseline saved in `-v3`; **no replay comparison was run**. `attempt_0001` is superseded. Record 06 |
| Job in hand | 7: the next job from `stepwise.py next --app-run 2026-11-12-0001` (not yet launched; no record) |
| Stack | idle, five services healthy, target `/opt/app/targets/freeciv`, profile `dev`, recording `record` |
| Target | `b1b0768bfaca9b2fae68f9466defe1e80636e9fa`, status clean |

## How to continue

```sh
.venv/bin/python deploy/dagster/bin/stepwise.py next --app-run 2026-11-12-0001
# four checks, write the next record under docs/tasks/, then
.venv/bin/python deploy/dagster/bin/stepwise.py accept --app-run 2026-11-12-0001 \
  --job <job id> --tag freeciv-b1b0768b-v3 --target-tag freeciv-b1b0768b-v1
```

Pass the run id explicitly on every command. Run ids roll to the UTC date; one script of this
walk addressed the previous day's run after midnight (it wrote nothing; see record 05).

## Job 6 (record 06)

- Accepted on `attempt_0002` after an anchor defect was fixed (`38777f90`: history is anchored at the
  checked-out `HEAD`, not the local `main` tip). The first attempt read history past the pin.
- Expected-list rows 11 to 14 were added by the user's decisions of 2026-11-12 (timing gaps,
  symbol and parse gaps, line-history size bound, change-log gaps and `timestamp_anomaly:1`).
- Open, non-blocking: the job binds 32,071 change-log path mentions where an independent count
  finds 38,056 present in the job's file set (record 06, sizing section); a question for T-097.
- Run the WSL command itself as the background task; a `&` inside `bash -lc` dies with the shell.

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

- Nothing blocks job 7. Whether to push the local walk-document commits is the user's call.
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
