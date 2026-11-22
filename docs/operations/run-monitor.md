---
title: "Five-minute review monitoring"
kind: "operations"
subsystem: "reporting and metrics"
status: "current"
jobs: []
---
# Five-minute review monitoring

The one-shot monitor derives a small text report from the existing authoritative
`data/logs/pipeline.jsonl`. It is not another runner, logger, model tool or daemon.
The repository-agent [monitor skill](../../.claude/skills/monitor-review-run/SKILL.md) contains the
standalone kickoff prompt and session scheduling/terminal cleanup procedure.
Do not schedule against a guessed run or after a preflight that never submitted a run.

From the owning Linux checkout, using its own environment:

```sh
.venv/bin/python -m appsec_review.observability.monitor --help
.venv/bin/python -m appsec_review.observability.monitor \
  --runs-root runs --run-id EXACT_APP_RUN_ID --dagster-run-id EXACT_DAGSTER_UUID --save
```

Omit the Dagster flag only for an explicitly non-Dagster run. `--json` prints the structured
`appsec-review/run-monitor/1` snapshot. `--save` writes only
`runs/<id>/data/telemetry/monitor/{checkpoint,snapshot}.json`; it never appends pipeline events.
Without it the command does not write files. The checkpoint is a bounded derived cursor/cache,
not another authoritative event stream. Keep one monitor owner per run.
The command never loads the current profile or registry to guess the run graph or dispatches.
It does not contact Dagster: the agent separately uses the run owner's approved exact read-only
status command, names its observation time and resolves conflicting evidence explicitly.

## Meaning and limitations

- Job denominators come only from a validated, hash-referenced frozen actual graph on
  `GRAPH_STARTED` or `RUN_GRAPH_SNAPSHOT`. GraphRunner records selection before its planner/handlers;
  Dagster begin operations record it before admission for an explicit application ID, or
  immediately after admission allocates a new ID and before task dispatch. The immutable
  `data/configuration/graphs/<sha256>.json` (`appsec-review/run-graph/1`) contains selected
  job/dependency IDs, application and optional Dagster IDs, resolved configuration SHA-256,
  profile and measured implementation/source SHA-256 (null when unavailable).
  Dagster uses the submitted op/step selection, not the full compiled graph when subsetted.
  `partial_jobs` names jobs with only some operations selected; whole-job denominators stay unknown
  for that case. A unit-only reexecution without a begin operation cannot publish a new selection;
  its missing/mismatched exact Dagster snapshot remains unknown, not a reused older denominator.
  It adds no new lifecycle/status semantics or execution grants.
  Enabled jobs in `resolved.json` are only configuration, not proof of selection.
  A missing historical graph makes total/completed/running/remaining unknown. Do not use the current
  registry size. Configuration bytes are checked against the frozen manifest; source identity is
  read from the run-owned implementation binding and hash-checked release manifest, not current HEAD.
- Completed means terminal, **not successful**: the status partition separately shows succeeded,
  completed-with-gaps, failed, cancelled, timed-out, not-applicable, partial and blocked. Remaining
  includes queued/unknown jobs, not running or terminal jobs. One latest observed attempt per job
  contributes to these counts; attempts/retries and reused work are reported separately.
  Reuse with no terminal disposition is unknown, never presumed fresh successful execution.
- Progress belongs to the **current execution epoch**, beginning at a fresh `RUN_STARTED` or
  a new dispatch/graph selection. Old attempts remain in the explicitly historical attempt totals
  and model/cost totals (`application_run_all_epochs`), but old completions do not advance the current
  graph. A prior attempt enters current progress only after a current start/queue admission or
  an actual `JOB_REUSED` observation. A plan alone is not consumption. Graphs missing from the current
  epoch cannot borrow the older epoch's denominator; current subset graphs exclude historical jobs.
  `epoch_attempts` and `attempts` keep these scopes separate, and epoch changes invalidate deltas.
- Whenever an effective Dagster UUID is known—explicitly supplied **or inferred** from current owned
  run/graph records—terminal confirmation requires both a valid graph bound to that
  UUID and a current terminal event positively naming the same UUID. Missing, invalid or unbound graph
  evidence, an untagged terminal, and another dispatch's terminal cannot trigger a final summary or
  schedule cleanup. Matching graph metadata alone does not make a late old terminal current.
  Only a genuinely non-Dagster direct run with a valid current graph can use an untagged application
  terminal. A claimed UUID in a contradictory snapshot is an unconfirmed context, not permission to
  fall back to application success. Event-stream coverage and lifecycle/dispatch confirmation differ.
- Epochs, terminals, and attempt admissions use the same dispatch-ownership rules. Both the flat
  `dagster_run_id` and the actual `JOB_STARTED` emitter's nested `orchestration.system/run_id` are
  recognized; conflicting or malformed identities are rejected. `JOB_STARTED`, `JOB_QUEUED` and
  `JOB_REUSED` must positively match the effective dispatch before contributing current progress.
  Task/job progress that omits a UUID may inherit only an exact, already admitted current
  `(job_id, attempt_id)` owner; explicitly foreign events never inherit. Run terminals cannot inherit
  attempt ownership. Reuse of an old attempt is current only when the reuse observation names the
  current owner. Foreign and ambiguous records remain historical/diagnostic, not current admissions.
- A fresh Dagster allocation emits `RUN_STARTED`, then `JOB_STARTED`, then the graph snapshot.
  The first matching snapshot enriches that existing owned epoch instead of resetting it. A genuinely
  new UUID/start creates a new epoch; repeated or late foreign metadata cannot reopen an older one.
  Checkpoints retain only the nested system/run identity, never workflow prose. Old checkpoints that
  lost admission correlation remain explicitly unconfirmed rather than guessing from the graph.
- Direct GraphRunner writes the existing `JOB_REUSED` observation when it actually consumes its
  accepted reuse decision, retaining attempt, disposition and handoff identity without reexecuting
  work or changing admission/reuse policy. Historical `RESUME_PLANNED` records retain only bounded
  structured job/action/hash fields in the monitor; unmatched planned reuse is unknown, not zero
  consumption. Whole-job reuse does not emit task reuse measurements: `reused_tasks` stays null,
  `reused_tasks_observed` remains the known count, and `reuse_gaps` / `reuse_accounting_complete`
  disclose that limitation. Old checkpoints missing structured resume observations name the gap.
- Models are grouped by served provider/model when available, requested pair otherwise; frozen
  configured pairs are shown separately. Roles/jobs identify hotspots. A retry count of three is
  not three new calls: only distinct invocation IDs count. Replay/cache results and reused tasks/
  jobs do not become new token usage. No subscription pricing or token-to-credit multiplier is used.
  A pre-dispatch refusal/cancellation stays in its hash-only execution receipt and is not a fresh
  model call; the monitor does not traverse those receipts to invent a provider call count.
- Input/output/cache/reasoning usage is included only when explicitly measured as nonnegative
  integers. Missing values remain null with measured/missing counts and reasons. `known_sum` is
  a lower bound whenever calls or usage are incomplete; zero is not manufactured for no measurements.
  Current transports may not report reasoning usage; that is unknown, not a calculated subset.
- `call_latency` and `queue_delay` use explicitly reported fields only. The bounded `Execution`
  writer measures the `infer(...)` transport boundary in `call_latency_ms`, on success and exceptions,
  and the accounting reservation/admission boundary in `queue_delay_ms` when present. An absent
  admission instrument is null, never an assumed zero. `queue_scope=accounting_reserve` does not claim
  to measure a provider's private queue; `latency_scope=infer_dispatch` may include transport-internal
  queuing. Both are persisted on the hash-only execution receipt and existing model completion event,
  and retained in `run-metrics/7.model_invocations`. Legacy/request roles use stable identifiers only.
  Provider-reported usage attached to invalid-output exceptions is retained even without a valid reply.
  Existing `duration_ms`
  remains separately labelled inclusive execution time (which may include admission/settlement).
  p50/p95 are nearest-rank values over measured samples with sample/missing counts. Summed execution
  is not concurrent wall time: the latter merges observed dispatch start/end intervals, which may
  include post-provider settlement, excludes replay and does not estimate unfinished calls.
- Time/token/retry top-three rows are investigation candidates, not proven waste.
  Invalid output, retries, timeouts and cancellations remain visible; high usage alone is not waste.
  Missing usage can also affect an apparently cheap hotspot. No prompt, response, tool argument,
  source excerpt, raw exception text or credential is added to this report.
- Deltas require the same run/dispatch/configuration/source/graph, increasing observation time,
  stable event generation, no restart/reset, and complete event coverage in both snapshots.
  Token deltas additionally require complete usage. Never subtract across runs or graph restarts.
- The bounded follower verifies event schema, run ID, sequence and timestamps and coalesces
  incidental/progress samples. It retains model/lifecycle events and never silently drops them.
  Each poll defaults to 16 pages of at most 256 events/1 MiB, at most 20,000 retained records,
  at most 8 MiB per identity JSON and 32 MiB checkpoint, and eight rows per detail table.
  `--pages 1..100` and `--rows 1..30` are explicit bounds. Overflow/backlog/torn tail/corruption/
  reset/missing inputs/omitted rows remain named. Exit 2 means incomplete event coverage.
  A capacity limit needs owner review, not a misleading all-time total.
- Quiet logs are not proof of a dead worker. Reports show elapsed/last-event/progress age and
  observed blockage events, not an automatic recovery decision. Future/stale observations and
  terminal conflicts need reconciliation with the owning dispatch.
- This monitor deliberately does **not** walk every receipt, invoke native validators or rebuild
  `run-metrics/7` each poll. It marks receipt verification unassessed: reported job status is not
  validated evidence, successful reuse, a security finding, completeness assurance or review quality.
  Use [metrics](metrics.md) and [terminal telemetry report](telemetry-report.md) when that separate
  receipt-backed analysis is wanted and authorized.

Model recording stays off. Structured telemetry/usage and hash-only execution receipts are distinct
from raw model recording, and monitoring never changes recording mode.
