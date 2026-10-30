# Telemetry and derived metrics

`runs/<run-id>/data/logs/pipeline.jsonl` is the canonical append-only event stream. Every record uses
`appsec-review/telemetry-event/1`, a contiguous sequence, stable event identity, UTC timestamp, and
run/job/attempt/step/task correlation. Details may add Dagster run/node, producer/tool invocation,
index shard, MCP session/invocation, model invocation, or finding-package identities.

The writer is process-safe and crash-recovering. It bounds depth, collection size, strings, and total
record bytes. Credentials, secret-like values, prompts, responses, raw model output, source text,
and query text are redacted. Telemetry uses request, guidance, reason, evidence, and artifact hashes.
Where a job explicitly needs raw provider or tool output for diagnosis, it stores bounded bytes as a
run-owned task artifact with access inherited from the run; those bytes are never copied into this
central event stream, and credentials remain prohibited.

Lifecycle families are:

- `RUN_*`, `GRAPH_*`, `JOB_*`, `STEP_*`, and `TASK_*` start and terminal events, including duration,
  reuse, disposition, and `COMPLETED_WITH_GAPS` where applicable.
- `TOOL_INVOCATION_STARTED/COMPLETED` for scanners and external tools, with immutable tool identity,
  retry, duration, result/gap counts, truncation, disposition, and error class.
- `MCP_TOOL_STARTED/COMPLETED` for transport calls and `RETRIEVAL_SUBOP_COMPLETED` for child spans.
- `MODEL_CALL_STARTED/COMPLETED` around inference calls (currently emitted by target analysis
  planning, project-build image repair, post-build security assessment, OWASP worker/independent
  assessment, and lead/hunt red/blue/verifier/judge cells), with
  provider/model/reasoning identities, guidance and request hashes, token/cache counts, duration,
  retry, status, and error class.
- `DAGSTER_QUEUE_DELAY`, written by the Dagster adapter when it claims a job attempt, with the
  Dagster run id and the delay in milliseconds since that Dagster run was created.
- `PROJECT_IMAGE_BUILD_STARTED`, `PROJECT_IMAGE_BUILT|REUSED|BUILD_FAILED`, and
  `BUILD_PROBE_REUSED` record project-image and cross-run probe decisions by recipe and image
  identity. `PROJECT_IMAGE_REPAIR_ACCEPTED|FAILED|REUSED` records bounded repair disposition and
  identities without Dockerfile, package, diagnostic, or model-response text. Probe compiler/linker
  commands use the ordinary `TOOL_INVOCATION_*` lifecycle.
- `LANGUAGE_STATIC_WORKFLOW_DISPATCHED` and `LANGUAGE_BUILD_WORKFLOW_DISPATCHED` record bounded
  routing decisions. They carry identities and counts, not raw commands, source, or model content.
- `FINDING_TRANSITION` for `NONE -> CANDIDATE -> CONFIRMED|REFUTED`. It carries the immutable finding
  package, evidence identities/count, actor class, and reason/evidence hash. Scanner observations are
  evidence records; they are never counted as confirmed findings without a valid transition.
- `REVIEW_SCOPE_CATALOGED`, `LANGUAGE_BUILDS_RECORDED`, and `CODEQL_SCOPES_RECORDED` point to
  immutable, hash-verified run receipts. They make workload, build, artifact, and missing-producer
  scope available to the metrics derivation without copying mutable aggregate counters into events.

## Interchange instrumentation

The [interchange upgrade](job-interchange.md) adds `HANDOFF_VALIDATED` and `HANDOFF_REJECTED`
alongside `HANDOFF_ACCEPTED`. Each event binds `handoff_reference`
(`path`, `sha256`, `size_bytes`), `duration_ms`, `execution_status`, `admission_status`,
`coverage_disposition`, `unit_count`, `gap_count`, and `retry_required`.
A rejection may use a null handoff reference only when a safe diagnostic publication is unavailable.
Accepted events retain `handoff_path`, `handoff_sha256`, and `completion_status` for existing
consumers. The event's completion status is bounded to known runtime terminals or `UNKNOWN`;
native producer status remains in receipt accounting, not arbitrary telemetry labels.
Validation events describe publication work, not repeated validation on checkpoint reuse.

`NATIVE_OUTPUT_RETAINED.retention_receipt` and
`OBSERVATION_PROVENANCE_VALIDATED.provenance_receipt` bind immutable retention/provenance
receipts; handoff events use `handoff_reference`. They describe retained bytes and resolving
observation references, not scanner-origin attestation or vulnerability confirmation.
Events carry bounded identities, durations, counts, and hashes,
never raw reports, source, argv, secrets, or per-result message text. The fixed work-counter names
are `handoff_validations`, `native_output_references`, `native_output_bytes`,
`observation_references`, and `provenance_gaps`; paths, rule IDs, gap reasons, and arbitrary producer
status strings must not become unbounded counter labels.
Native retention/provenance events take run/job/attempt identity explicitly from the publication
owner. Native reference/byte work counters also measure verified reuse consumption; they describe
logical reference processing, not fresh scanner execution or physical retained occupancy.

The interchange upgrade introduced `appsec-review/run-metrics/5`, adding `interchange` with schema
`appsec-review/interchange-metrics/1`. It derives publication/receipt identities and verifies the
referenced bytes and retention/provenance computation instead of trusting event-supplied counts.
Missing or tampered receipts are named integrity gaps, not zero work. Repeated publication/receipt
events deduplicate by identity, while reused evidence is not counted as fresh scanner work.
The closed groups are `handoffs`, `native_outputs`, `observations`, registered-job-only `by_job`,
and `integrity_gap_codes`. Section `accounting_complete` distinguishes measured accounting from
missing evidence; invalid/missing receipts yield null affected totals, not invented zeros. Rollups retain
coverage/execution/gap-code dimensions but never rule/path/hash/package/message labels.
Observation rollups also distinguish `provenance_complete_count` from
`provenance_incomplete_count` using receipt completeness, and `provenance_gap_count` sums common
observation `gap_ids` from the receipt computation. `interchange.duplicate_events` reports repeated
event identities without inflating the verified publication or receipt totals.
Handoff `duration_ms` has `count`, `sum`, `p50`, `p95`, and `max`, once per publication rather than
once per validated/accepted event. This is publication timing, not scanner runtime.
Interchange processing is bounded to 100,000 relevant events; exceeding it produces
`accounting_bound_exceeded` and incomplete affected accounting. The receipt is authoritative,
not the presence of a summary field. Integrated source and offline tests do not establish that a
deployed runtime has been rebuilt or accepted.

## Operation spans, progress and phases

[`observability/spans.py`](../../src/appsec_review/observability/spans.py) wraps bounded units of
job work in `operation_span`. Each span writes `OPERATION_STARTED` and `OPERATION_COMPLETED`
through the job's `EventLog`, so records land in the attempt `events.jsonl` and the fsynced
`pipeline.jsonl`. Correlation is `span_id`, `parent_span_id`, `operation_id` (the stage) and the
inherited `unit_id`, `scope_id`, `query_profile`, `resource_lease_id` and `tool_invocation_id`.
The completion record carries `terminal_status`, `duration_ms`, `resources` and `work`.

The design aims to diagnose a slow unit from telemetry alone, without per-item events. All
per-item data is aggregated in memory on the span. Per span, new records are bounded to one start,
one completion and at most one progress record per progress interval.

### Resources

`resources` mixes two scopes; the scope is part of each value's meaning:

| Field | Source | Scope |
| --- | --- | --- |
| `cpu_user_seconds`, `cpu_system_seconds` | `os.times()` delta | process-inclusive |
| `logical_read_bytes`, `logical_write_bytes`, `physical_read_bytes`, `physical_write_bytes` | `/proc/self/io` `rchar`/`wchar`/`read_bytes`/`write_bytes` | process-inclusive |
| `read_syscalls`, `write_syscalls` | `/proc/self/io` `syscr`/`syscw` | process-inclusive |
| `thread_cpu_seconds` | `time.thread_time()` delta | the span's own thread |
| `thread_off_cpu_seconds` | `max(0, wall - thread_cpu)` (derived) | the span's own thread |
| `voluntary_context_switches`, `involuntary_context_switches` | `getrusage(RUSAGE_THREAD)` `ru_nvcsw`/`ru_nivcsw` | thread |
| `block_input_ops`, `block_output_ops` | `ru_inblock`/`ru_oublock` | thread |
| `major_page_faults` | `ru_majflt` | thread |

`measurement_scope` remains `process_inclusive_not_additive` and `measurement_source` is
`os.times/proc-self-io/getrusage-thread/thread_time`. `rusage_scope` is `"thread"`, or null with
`rusage_unavailable_reason`: `rusage_thread_unavailable` where `RUSAGE_THREAD` is unavailable (for
example off Linux), or `span_exited_on_another_thread` when the span ended on a different thread
than it started on (the thread values are then also null). I/O and
syscall values are null with `io_unavailable_reason` when `/proc/self/io` is unavailable.
`child_cpu_seconds` and `peak_rss_bytes` stay null with their existing reasons. An unavailable value
is null with a reason, never zero. Process-inclusive values include concurrent threads and must not
be added across overlapping spans. Thread-scoped values exclude work the span hands to other
threads or child processes, so they are not additive with process-inclusive values. Voluntary
context switches and thread off-CPU time are the cheap, always-on blocked-time signal.

### Sampling configuration

```toml
[runtime]
operation_progress_interval_seconds = 60  # OPERATION_PROGRESS cadence; 0 disables progress
operation_sample_interval_seconds = 1     # thread-state sampling cadence; 0 disables sampling
```

Values must be finite, non-negative numbers of seconds. With both at `0` no span is registered with
the sampler. The settings are part of the run's frozen configuration.

### Thread states and fsync timing

Each span records its native thread id. A single lazily started daemon process sampler reads
`/proc/self/task/<tid>/stat` (state) and `/proc/self/task/<tid>/wchan` once per sample interval
(default 1 s) for each registered active span and accumulates:

```text
thread_states = {"samples": n, "R": n, "S": n, "D": n, "other": n,
                 "top_wait_channels": [{"symbol": "jbd2_log_wait_commit", "samples": n}, ...]}
```

At most five wait channels are reported. A `wchan` symbol that does not match
`[A-Za-z0-9_.]{1,64}` is recorded under the wait-channel symbol `other`, as is any new symbol once a
span has tracked 64 distinct symbols. Estimated blocked (uninterruptible) time is
`D / samples × wall`; it is a sampled estimate, not kernel-accounted delay. Spans shorter than one
sample interval report `samples: 0`. Kernel delay accounting (`delayacct`) is deliberately not used:
it is disabled by default and does not cover journal-commit waits. Nothing here requires root.

Storage fsyncs on the hot path (`storage/atomic.py`, `storage/shared.py`,
`storage/admission.py`) go through `timed_fsync`, which counts `fsync_calls` and records phase
`storage.fsync`. The telemetry writers themselves are not instrumented. SQLite-internal fsyncs are
not counted; they appear as off-CPU time in the `index.sqlite_*` phases and as D-state samples.

### `OPERATION_PROGRESS`

Every progress interval the sampler writes `OPERATION_PROGRESS` for each
registered span open for at least one interval. It uses the span's `EventLog`, so the last record is
fsynced in `pipeline.jsonl` and survives SIGKILL of the worker as the span's last known state. The
record carries the span correlation, `progress_sequence`, `progress_interval_ms`, `elapsed_ms`, and
cumulative `resources`, `work`, `expected`, `phases` and `thread_states`, plus the instantaneous
`thread_state_now` and `wait_channel_now`.

Progress `resources` have the same fields, but `measurement_source` is
`os.times/proc-self-io/proc-self-task`: the sampler cannot call `getrusage` for another thread, so
thread CPU, context switches and major faults come from `/proc/self/task/<tid>`, and block
input/output operations are derived from that thread's I/O bytes in 512-byte units. Where those files
are unavailable the thread values are null with `rusage_unavailable_reason:
"proc_thread_unavailable"`. Do not compare progress and completion thread values as if they used
one source.

`OPERATION_PROGRESS` deliberately uses `elapsed_ms`, not `duration_ms`, carries no
`terminal_status` or `disposition`, and nests counts under `work`. It therefore does not affect
lifecycle pairing or gaps, duration totals (`duration_ms_by_event`, `operations`),
`throughput_totals`, `dispositions`, `completed_work_count`, or the OpenVEX metrics filter. Repeated
progress records for one span are distinguished by `progress_sequence`, not deduplicated as one.

`OPERATION_COMPLETED` adds `progress_count`, `progress_write_failures`, `sampler_errors` and
`progress_unavailable_reason`. The reason is null when progress was possible, otherwise one of:

| Reason | Meaning |
| --- | --- |
| `active_span_limit` | 32 spans were already sampled; this span was not sampled. |
| `sampling_disabled` | Both intervals are `0`. |
| `progress_disabled` | Progress interval is `0`; thread-state sampling may still run. |
| `sampler_unavailable` | The sampler thread could not start. |

Sampler exceptions are swallowed and counted in `sampler_errors`, never raised into the job; the
registry is reset in forked children, and the thread exits when no span is registered.
`EventLog.write` serializes appends with a process-local lock so sampler and job-thread records
cannot interleave.

### Phases, counters and expected totals

`operation_phase(name)` times a sub-phase and accumulates it on the innermost active span (the same
attribution rule as `count_work`; a no-op without a span):
`phases[name] = {count, wall_ms, thread_cpu_ms, off_cpu_ms}`. It reads only monotonic and
thread-CPU clocks. Phase names are a closed vocabulary (an unknown name raises `ValueError`) and a
span holds at most 32 distinct phases. Nested phases are inclusive: a phase's time includes any
phase inside it, so phase times are not additive. The initial vocabulary is:

| Phase | Where |
| --- | --- |
| `index.prepare` | `IndexBuilder.build` entity/relation deduplication |
| `index.sqlite_write` | DDL, inserts and commit |
| `index.sqlite_vacuum` | reserved; `IndexBuilder.build` runs no `VACUUM` and never records it |
| `index.digest` | shard SHA-256 |
| `index.publish` | `adopt_private_file` hard-link (or cross-filesystem copy) into the shared object store |
| `index.link` | `os.link` of the published shard |
| `index.custody_bind` | custody owner binding |
| `index.lock_wait` | artifact-indexing shard lock wait |
| `index.reuse_verify` | artifact-indexing shard reuse verification |
| `storage.fsync` | `timed_fsync` storage fsyncs |
| `storage.copy` | storage copy paths that also count `copy_bytes` |

The closed `work` counter vocabulary adds `receipts_processed`, `artifacts_processed`,
`shards_built`, `shards_reused`, `entities_written`, `relations_written`, `invocations_scanned` and
`fsync_calls`. `expect_work(name, total)` declares an expected total for a counter on the innermost
span (`expected[name]`; a known counter and a non-negative integer; the last value wins), so progress
can show `artifacts_processed` against its expected total and a completion ratio.
Counters and phases describe instrumented boundaries only; an absent counter is not a measured zero.

All of this attaches to an active span, so replacing `operation_span` (the switch used by the
operation-telemetry overhead comparison) disables the sampler, progress records, phases and the
new counters as well. See
[performance assurance](../operations/performance-assurance.md#metrics-and-comparison).

## Existing derived views

`appsec-review metrics --run-id <id>` deterministically rebuilds and persists
`data/telemetry/summary.json` using `appsec-review/run-metrics/6`
(historical summaries use `/5` or earlier; `/5` summaries lack `operation_progress`,
`operation_hotspots` and the span `phases`/`expected`/`thread_states`/`progress_count` fields, and
their absence is not zero). It separates end-to-end wall time, per-job wall spans, summed
concurrent task time, queue delay, completed and still-running work, reuse, processed counts/bytes,
critical-path candidates, and bounded p50/p95/max rankings by stable operation identity. The JSONL
events remain authoritative; the summary is a regenerable operator view.
The [end-of-review telemetry report](../operations/telemetry-report.md) renders both, read-only,
into one LaTeX/PDF rollup per run.

Operation spans feed three views. `resource_spans` holds one row per `OPERATION_COMPLETED`, now
including `phases`, `expected`, `thread_states` and `progress_count`. `operation_progress` (at most
200 rows, ordered by `started_at`) lists spans with `OPERATION_STARTED` and no
`OPERATION_COMPLETED`. Each row carries the correlation (`run_id`, `job_id`, `attempt_id`,
`span_id`, `parent_span_id`, `stage`, `unit_id`, `scope_id`), `started_at`, and the last progress
snapshot (`last_progress_at`, `progress_sequence`, `elapsed_ms`, `work`, `expected`, per-counter
`completion_ratio`, `phases`, `thread_states`, `thread_state_now`, `wait_channel_now`), plus a
`state`. The state is `running`, or `lost` when a job terminal closed the attempt or the last
progress is older than three times that record's `progress_interval_ms` relative to the newest run
event. A span with no progress record has `last_progress_at: null` and can become `lost` only through
its closed attempt. `operation_hotspots` ranks the top 20 completed spans by `duration_ms`, with
`job_id`, `attempt_id`, `span_id`, `stage`, `unit_id`, `terminal_status`, `duration_ms`,
`thread_off_cpu_ratio`, `d_state_ratio`, `top_wait_channel`, `dominant_phase` and
`dominant_phase_wall_ms` (the phase with the largest `wall_ms`), and the per-item rates
`ms_per_artifact` (`duration_ms / artifacts_processed`) and `fsync_calls_per_shard`
(`fsync_calls / (shards_built + shards_reused)`). A ratio or rate is null when its inputs were not
recorded or its denominator is zero.
Operational diagnosis is described in
[metrics operations](../operations/metrics.md#diagnosing-a-slow-or-stuck-step).

The additive `project_image_builds` view reports preparation starts, fresh builds,
reuse, failures and failures by language family. Image preparation is paired by
`build_unit_id`, including `PROJECT_IMAGE_BUILT`, `PROJECT_IMAGE_REUSED` and
accepted-repair reuse as terminals; unrelated repair failures do not close that
phase. A handled `PROJECT_IMAGE_BUILD_FAILED` is a nested preparation gap, not a
failed Dagster step or `TASK_FAILED`. Concurrent starts/terminals need not be
adjacent. Ordinary split task failures separately close FAILED step/attempt state;
new-contract terminal Dagster failure recording supplies graph/run terminal events
when success-only finalizers are skipped. Historical events are not rewritten.

The additive `owasp` section resolves `OWASP_ASSESSMENT_RECORDED` to the hash-verified workbench
report. It retains each publication attempt and the latest coverage denominators without summing
the same rows across retries. A missing, changed, or invalid latest receipt is a named gap, not a
fallback to older coverage. New dispatch starts and completed calls remain separate, so an
in-flight request is not zero work or completed coverage. Input-index retrieval, batch
source/citation resolution, and model-requested expansion are separate counters; worker metrics carried into independent review
are read once from the final report, not summed again from intermediate worker events.
`OWASP_MODEL_REUSED` records verified reuse with no new dispatch, and
`OWASP_RETRIEVAL_COMPLETED` distinguishes succeeded, denied, failed and budget-skipped requests.

The additive `review_flow` section retains control-evidence projection and package/lane publication
milestones, manifest pins, and the latest cell disposition per attempt/cell. Cell metrics distinguish
fresh work, verified reuse, and not-launched work. Historical retrieval counts on reused cells are
not fresh queries. Absent milestones mean unrecorded execution, not successful zero-work stages.
Generic task/step/operation events supply stage timing and failures across the entire graph.
`model_invocations` now retains role/persona, cell, batch/package/lane, job-attempt/task correlation,
transport status, and available served identities. Transport success does not establish valid
assessment output: the OWASP attempt/cell receipt retains that separate disposition. Provider token
usage stays nullable; invalid usage is named rather than aggregated as zero. Configured recording
replay is labelled separately and contributes neither new inference nor historical token usage
to fresh-call totals. Cell dispatch attempts remain distinct from that fresh-call count.
Neither model counts nor publication/cell success establish findings or safety, and scripted/recorded transports do not
establish live-provider efficacy. Raw prompts, responses, source, and exception text are not emitted
by the shared model-call measurement helper.

Version 4 adds the top-level `codeql` section (`appsec-review/codeql-execution-metrics/1`). Every
CodeQL action (database, analyze, compile, export) is one row derived from its
`TOOL_INVOCATION_COMPLETED`, `CODEQL_ACTION_SKIPPED`, or `CODEQL_ACTION_FAILED` event. Each event
carries language, source languages, build mode, action, query pack, pack version, and suite; runtime
comes from the hash-verified execution receipt. Rows are aggregated by query pack, by language, by
query pack x language, and by source language, each with per-status counts and runtime
total/min/max/p50/p95. Per-query rows come from the run-owned
`appsec-review/codeql-query-metrics/1` document named by the event's `query_metrics` identity;
an absent source is a named gap, never zero. See
[CodeQL execution telemetry](../operations/codeql-analysis.md#execution-telemetry).

The `review` section uses `appsec-review/review-metrics-semantics/1`. Source classification is
`appsec-review/source-counting/1`: language is extension-based; SLOC is the number of non-empty
UTF-8 physical lines (comments included); generated paths have a `generated` or `gen` segment;
vendored paths have a `vendor`, `vendors`, or `third_party` segment; and tests have a `test`,
`tests`, `spec`, or `specs` segment or a `test_`/`spec_` filename. `dist`, `build`, and
`node_modules` trees are excluded and reported as coverage gaps rather than silently counted.
Generated, vendored, and test files remain in language totals and are also reported as explicit
subtotals. Bounded, excluded, undecodable, or missing catalog input is a source coverage gap.

The additive `tree_sitter` view (`appsec-review/tree-sitter-metrics/1`) re-verifies correlated
start, execution and validated-output receipts, including invocation/run/job/attempt identity.
It reports per-invocation outcomes/resources/files/nodes/truncation, job-attempt groups and reuse;
timing separates summed invocation work, elapsed window, covered wall time and maximum concurrency.
Missing or conflicting receipts/resources keep explicit gaps, nulls and completeness flags.
`memory_peak_bytes` is the maximum individual container peak, not concurrent aggregate memory.

Build outcomes come from accepted language-build receipts. A reused successful receipt counts as
reuse rather than fresh success; any receipt with producer gaps also increments the gap count.
Artifact reference totals count each build-unit-to-artifact edge. Content-deduplicated totals count
one SHA-256 identity globally, while per-language/build-unit/family groups retain every reference.
Conflicting sizes for one digest are an integrity gap.

CodeQL database and query time resolve to immutable execution receipts; reused checkpoints resolve
to immutable checkpoint receipts and contribute zero work. Groups retain scope, language, project
root, build unit, profile, and query-suite identity. `summed_work_ms` sums producer work, while
`wall_span_ms` is the union of event intervals and therefore does not double-count concurrent work.
The view includes p50, p95, maximum, fresh/reused counts, and language/project/profile rollups.
Missing receipts, failed producers, and planned scopes without timing remain explicit gaps.

Raw SARIF/tool observations are not finding counts. The only authoritative defect/vulnerability
lifecycle metrics are the existing `FINDING_TRANSITION` state counts. TODO: before reporting
triaged-away/refuted and confirmed defect or vulnerability rates by taxonomy, implement immutable
transition receipts that bind a finding package to its observation identities, normalized defect
or vulnerability classification, prior and new state, actor class, reason hash, timestamp, and
supersession identity. Metrics must reject broken transition chains and must never infer candidates
or confirmation from observation volume.

For fleet/control-plane state, `python deploy/dagster/bin/run_report.py` reports the live Dagster
run list alongside bounded slow-operation rankings collected from available summaries. It separates
completed, queued, genuinely running, stale, and orphaned Dagster records. `--stale-seconds`
controls classification; the command is read-only.

## Evidence-completion tracking (commissioned)

The user requires telemetry and metrics from the first implementation of the
[completion lanes](evidence-completion-and-remediation.md#11-parallel-implementation-decisions),
not instrumentation added after rollout. Integration `b702eb7` adds completion aggregates and
remediation/dossier events to the existing system. Checkpoint `18eae9f` adds aggregate parity for
real PoC/native statuses, capability maps, flags and nonadditive limits. Remediation follow-up
`e769645f` preserves unknown token dimensions/null versus genuine measured zero and emits unavailable
metadata. Final `dd9c9ad` adds actual chain composition/challenge/publication, PoC outcome,
gate capability/admission and report assembly events. The table below records the complete tracking
requirement, not a claim that every producer emits every dimension or provider usage measurement.

Reuse [`EventLog.write`](../../src/appsec_review/observability/events.py) through `context.events`
and [`aggregate_run_metrics`](../../src/appsec_review/observability/telemetry.py), retaining the
canonical pipeline stream and regenerable `data/telemetry/summary.json`. No separate telemetry
backend or Azure service is requested.

[`observability/completion.py::completion_metrics`](../../src/appsec_review/observability/completion.py)
first added `completion` to `appsec-review/run-metrics/3`; combined source `6975aef2` retains
the same `completion-process-metrics/1` semantics in `run-metrics/4`, alongside the existing
review and new CodeQL/OWASP/review-flow/Tree-sitter views.
Its `semantics` is `appsec-review/completion-process-metrics/1`, with
`authority: observational_process_metrics_not_security_evidence`. Fixed lanes are
`attack_chains`, `poc_generation`, `remediation_planning`, `remediation_validation`, `dossiers`,
`publication_gate`, `report_publication`. Chains are selected by inference `step_id=attack_chains`
or the `INFERENCE_REVIEW_ATTACK_CHAIN` event prefix; other lanes map fixed job ids.

Each lane contains `observed` and `events`. Each event has the following closed aggregate shape:

| Field | Meaning and bounded dimensions |
| --- | --- |
| `count`, `counters`, `outcomes` | Event count, allowlisted attempted-work sums and closed statuses; outcome maps retain their `outcomes`, `outcome_counts`, `by_kind` or `by_status` prefix. All seven actual PoC statuses are accepted: `compile_verified`, `compile_failed`, `artifact_generated`, `policy_denied`, `insufficient_evidence`, `not_applicable`, `unsafe_to_attempt`. Native adapter outcomes include `passed`, `baseline_failed`, `patched_failed`, `unsafe`. |
| Capability maps | `attachment_counts`, `gap_counts`, `omitted_counts`, `certified_outcome_counts` become prefixed counters; `dispositions` become prefixed outcomes and Boolean `enabled` values become flags. Only `poc_generation`, `attack_chains`, `remediation_planning`, `remediation_validation`, `dossiers` are valid capabilities. These are event observations, not a replacement for frozen configuration or accepted manifests. |
| `flags` | Counts by Boolean value for `explicit_poc_admission`, `frontier_truncated`, `pdf_requested`, `render_failed`, `baseline_attempted`, `patched_attempted`, `usage_unavailable`, and the fixed capability `enabled` map. |
| `dimensions` | `kind`: `confirmed_finding`, `poc`, `refuter`, `weakest_link_verifier`; `adapter`: `native_syntax`; `role`: `remediation_writer`, `remediation_reviewer`. No arbitrary identity becomes a label. |
| `limits` | Per-event observed `{min,max}` ranges for `max_dossiers`, `max_source_excerpts`, `max_evidence_rows`. Configured limits are **never summed** across retries or counted as work. |
| `unavailable_token_measurements` | Number of explicit-null `input_tokens`, `output_tokens`, `cache_tokens` measurements, not missing turns. Separately, `counters.usage_unavailable_count`, when emitted by a producer, counts turns with unavailable usage. Omitted fields are not invented as zero or counted as explicit nulls. |
| `duration_ms` | `count`, `p50`, `p95`, `max`, `summed_work`; summaries are null when no duration was emitted. |

Capability `enabled`/`dispositions` maps are admitted only for
`FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED` in the publication-gate lane (`b9e69d17`).
Generic step lifecycle disposition lists are not capability maps or measurement failures.
The [historical owner all-lane result](../reviews/evidence-completion-documentation-inventory.md#acceptance-ledger)
at `039b24e4` observes all seven lanes with zero measurement gaps while preserving legitimate
review/source/redaction gaps. It uses offline model/compiler/renderer boundary doubles, not live
runtime reproduction. Zero telemetry gaps does not establish complete evidence or current-main
acceptance.

Invalid/nonfinite/negative/oversized measurements and invalid capability/outcome mappings increment
`measurement_gap_count`; at most 200 named `measurement_gaps` are retained.
`COUNTERS`, `OUTCOMES`, `OUTCOME_FIELDS`, `LIMITS`, `CAPABILITIES`, `CAPABILITY_COUNTERS`, `FLAGS`
and `DIMENSIONS` are closed in the source module. Aggregator support for a field does not prove a
producer emitted it; synthetic metrics fixtures do not substitute for actual process observations.
Checkpoint `0ece65d3` adds the real chain challenge map's `not_launched` status to the aggregate
allowlist, with a full `CellStatus`-shaped regression. Its presence still does not establish
accepted challenge coverage. Aggregate counters
exclude arbitrary text, candidate ids, paths, provider prose and raw payloads.

These are event-scoped **attempted work**: retries count; neither stage totals nor overlapping
durations may be summed as unique candidates or end-to-end wall time. `observed=false` is not a
measured zero or a complete missing-producer audit. Producer manifests, frozen config and
integrity/coverage accounting remain necessary.

| Surface | Required process observations |
| --- | --- |
| Stages and attempts | Start/terminal correlation, duration, attempt/reuse and stage progress, enabled/disabled or empty-scope disposition, caps, gaps and failures; unmatched/conflicting lifecycle records remain explicit. |
| PoC candidates | Eligible and terminal candidate counts; policy refusal, unsupported/unavailable, compile outcome, cap/timeout and producer failure. Compilation remains distinct from runtime execution. |
| Chains | Seed/composition/challenge counts, terminal continuity decisions, bounds and missing-edge/verification gaps before ledger sealing. Metrics cannot replace the accepted chain manifest. |
| Remediation | Confirmed-only intake, proposal outcomes and byte-edit applicability; adapter selections, static/build/manual outcomes, rejections and adapter failures. No `fixed` or runtime-success counter follows from a static/build check. |
| Dossiers | Eligible confirmed-finding/PoC counts, source retention, per-item render status, PDF success/failure/timeout, output counts, duration, caps and cleanup gaps. A retained LaTeX source is not a successful PDF. |
| Gate and report | Accepted input/capability accounting, certified attachment counts, integrity failures and missing-producer/coverage gaps, without inventing target evidence from throughput. |
| Model work | Correlated model/retry/duration and provider usage where emitted. Unknown token/cache/cost data remains unknown, not an instrumented zero or an inferred bill. |

Use low-cardinality stage/lane/status/adapter/error-class aggregates. Exact run/attempt/candidate
and artifact hashes are diagnostic correlation fields, not unbounded metric-label dimensions.
Do not double-count per-item outcomes again as stage summaries or add overlapping inclusive
durations as wall time. Failed, skipped, capped and disabled work must remain distinguishable.

Producer fields must be allowlisted before `context.events.write`: its attempt log receives fields
before the central writer bounds/redacts them. Never emit source, patch or PoC payloads, raw prompts,
credentials or arbitrary model/compiler diagnostics into either stream. Use counts, closed statuses,
bounded error classes and resolving hashes instead; existing key-based redaction is not permission
to log arbitrary content under a different key. Metrics are operational accounting, not admissible
security evidence or a public dossier payload. See [metrics operations](../operations/metrics.md)
and the [dossier input inventory](dossier-data-inventory.md).
