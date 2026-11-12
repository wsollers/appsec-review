# Walk state: Freeciv at `b1b0768b`

The current position of the walk whose terms are in [freeciv-b1b0768b.md](freeciv-b1b0768b.md).
The walker rewrites this file at every acceptance, stop and restart
([walk charter](../processes/walk-charter.md), section 7). A fresh session compares it with the
host before acting.

**As of:** 2026-11-12 about 04:00 EST, `main` and `origin/main` at `a6c29142` (pushed at the user's
"Yes, merge and push"; the charter is on `main`). Written by the walker after the replay that followed the
merge of `origin/main`; no job has run since.

| Item | Value |
| --- | --- |
| Run | `2026-11-12-0001` (earlier runs `2026-11-11-0007` to `-0009` are retained and are not the baseline) |
| Corpus namespace | `freeciv-b1b0768b-v3`; target tag `freeciv-b1b0768b-v1` |
| Overlay | `freeciv-b1b0768b/capacity-overlay.toml` (`cpu = 20`, `io_slots = 4`) |
| Accepted | jobs 1 to 5: `job_model_connectivity`, `job_image_pin_verification`, `job_target_acquisition`, `job_review_intake` (0 gaps each), `job_target_catalog` (28 gap records, 5 causes, all on the expected list). Records 01 to 05 |
| Accepted attempts | job 1 `attempt_0004`, jobs 2 to 4 `attempt_0003`, job 5 `attempt_0003`; every replay compared equal to its preserved key (0 differences) |
| Next job | 6, `job_source_history_analysis`: not launched |
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

## What job 6 should expect

- Expected duration: unknown (first run on this target). Freeciv has a long history; the
  configured history bounds being reached is on the expected list, anything else is not.
- First real run of the change-log unit (T-097). The inventory holds `ChangeLog` (2.8 MB, a plain
  `git log` dump with no file lists) and `ChangeLog-1.0-S3_0` (9.5 MB, `svn log -v`, paths under
  `/trunk/`). Its author expects unbound paths, so the unit ends PARTIAL and the job
  `COMPLETED_WITH_GAPS`; `changelog.json` will be tens of MB. T-097's "done when" asks for the
  format detection, entry counts, bound-file ranks and gaps to be checked against the two files,
  and for no author name, address or message text in any output.
- The source-history GitHub enrichment uses this shell's `gh` login (the stack prints
  `GITHUB_TOKEN: using this shell's gh login`); whether it reaches the network during the job is
  to be observed, not assumed.

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

- The go-ahead to launch job 6 in a fresh session.

## In flight

- Unmerged local branches held until after the walk: `wave3-composer`, `wave2-osv`.
- `wave3-fixtures` (`6055d078`) was declined: on current `main` it adds two collection errors and
  its fixtures append release ids that `main` now declares. It needs rebasing by its author.
- Design session `dfd-threat-model` (branch of that name, not merged) holds T-107 and T-108.
- The nightly data sync is stopped and the feeds are stale (T-106); restarting it is the user's.
