# Run log and idle watchdog

One JSON-lines file per run: `appsec-review-process/runs/<run-id>/data/logs/pipeline.log`. Daemons and other
processes with no run write to `appsec-review-process/logs/pipeline.log`.

- **Sessions.** The file is appended to at intake and at each resume. Every session starts with three lines of
  `#` (80 wide) and one `banner` record (`session start: intake|resume`). Written once per Dagster run: the
  first step of a Dagster run wins a marker file `data/logs/.banner-<dagster-run-id>`.
- **Record.** `ts, run, job, step, pid, proc, who, attempt, level, msg`. `who` is the id of the thing logging
  (`claude:<pid>`, `reviewer-03`, a pool instance). `msg` is capped at 1024 characters. Levels: info, warn, error, banner.
- **Context.** Every Dagster op that uses `pipeline_log_dagster.op` (all ops in `dagster_workflow.py` and
  `orchestrator/dagster/definitions.py`) binds run (from the `engagement_run_id` tag), job (op name), step key and
  attempt (Dagster run id), and logs `step start` / `step finished after Ns` / `step failed ...`. Workers set finer context with
  `pipeline_log.set_context(...)` / `with pipeline_log.context(who=...)`; children inherit `APPSEC_LOG_*` environment variables.
- **Never blocks.** `pipeline_log.log()` appends to a bounded in-memory buffer under a lock held only for the append; a
  writer thread does the IO with no lock held (line-aligned `O_APPEND` batches, safe across processes).
- **Tail.** `orchestrator/tail-run-log.sh <run-id> [--level warn] [--job X] [--who X] [--from-start] [--raw]`. Query with
  `jq -R 'fromjson? | select(.level=="error")' <file>` or `rg '"job":"07-' <file>`.
- **Env.** `APPSEC_PIPELINE_LOG=<file>` forces one file; `off` disables; `APPSEC_RUNS_ROOT` locates runs.

## Idle watchdog (`review_cli._dispatch_streaming`)
Every model call heartbeats every `APPSEC_HEARTBEAT_SECONDS` (default 30) with `events=N last=<type> idle=Ns`. When no stream
event arrives for `APPSEC_IDLE_WARN_SECONDS` (default 300, 0 = off) it logs a `warn` `IDLE` line (repeating every interval).
`APPSEC_IDLE_KILL_SECONDS` (default 0 = never) kills the process after that many idle seconds and returns `idle_killed: true`
(the caller sees the same missing-result path as a timeout). The ordinary `timeout` still applies.
