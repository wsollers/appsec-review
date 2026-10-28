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
  planning, project-build image repair, and post-build security assessment), with
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

`appsec-review metrics --run-id <id>` deterministically rebuilds and persists
`data/telemetry/summary.json` using `appsec-review/run-metrics/3`. It separates end-to-end wall time, per-job wall spans, summed
concurrent task time, queue delay, completed and still-running work, reuse, processed counts/bytes,
critical-path candidates, and bounded p50/p95/max rankings by stable operation identity. The JSONL
events remain authoritative; the summary is a regenerable operator view.

The `review` section uses `appsec-review/review-metrics-semantics/1`. Source classification is
`appsec-review/source-counting/1`: language is extension-based; SLOC is the number of non-empty
UTF-8 physical lines (comments included); generated paths have a `generated` or `gen` segment;
vendored paths have a `vendor`, `vendors`, or `third_party` segment; and tests have a `test`,
`tests`, `spec`, or `specs` segment or a `test_`/`spec_` filename. `dist`, `build`, and
`node_modules` trees are excluded and reported as coverage gaps rather than silently counted.
Generated, vendored, and test files remain in language totals and are also reported as explicit
subtotals. Bounded, excluded, undecodable, or missing catalog input is a source coverage gap.

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
metadata. Final PoC/gate/report/chain instrumentation is still being reconciled. The table below records
the complete tracking requirement, not a claim that every producer already emits every dimension.

Reuse [`EventLog.write`](../../src/appsec_review/observability/events.py) through `context.events`
and [`aggregate_run_metrics`](../../src/appsec_review/observability/telemetry.py), retaining the
canonical pipeline stream and regenerable `data/telemetry/summary.json`. No separate telemetry
backend or Azure service is requested.

[`observability/completion.py::completion_metrics`](../../src/appsec_review/observability/completion.py)
adds `completion` to `appsec-review/run-metrics/3` without changing the existing review views.
Its `semantics` is `appsec-review/completion-process-metrics/1`, with
`authority: observational_process_metrics_not_security_evidence`. Fixed lanes are
`attack_chains`, `poc_generation`, `remediation_planning`, `remediation_validation`, `dossiers`,
`publication_gate`, `report_publication`. Chains are selected by inference `step_id=attack_chains`
or the `INFERENCE_REVIEW_ATTACK_CHAIN` event prefix; other lanes map fixed job ids.

Each lane contains `observed` and `events`. Each event has the following closed aggregate shape:

| Field | Meaning and bounded dimensions |
| --- | --- |
| `count`, `counters`, `outcomes` | Event count, allowlisted attempted-work sums and closed statuses; outcome maps retain their `outcomes`, `outcome_counts`, `by_kind` or `by_status` prefix. All seven actual PoC statuses are accepted: `compile_verified`, `compile_failed`, `artifact_generated`, `policy_denied`, `insufficient_evidence`, `not_applicable`, `unsafe_to_attempt`. Native adapter outcomes include `passed`, `baseline_failed`, `patched_failed`, `unsafe`. |
| Capability maps | `attachment_counts`, `gap_counts`, `omitted_counts` become prefixed counters; `dispositions` become prefixed outcomes and Boolean `enabled` values become flags. Only `poc_generation`, `attack_chains`, `remediation_planning`, `remediation_validation`, `dossiers` are valid capabilities. These are event observations, not a replacement for frozen configuration or accepted manifests. |
| `flags` | Counts by Boolean value for `explicit_poc_admission`, `frontier_truncated`, `pdf_requested`, `render_failed`, `baseline_attempted`, `patched_attempted`, `usage_unavailable`, and the fixed capability `enabled` map. |
| `dimensions` | `kind`: `confirmed_finding`, `poc`, `refuter`, `weakest_link_verifier`; `adapter`: `native_syntax`; `role`: `remediation_writer`, `remediation_reviewer`. No arbitrary identity becomes a label. |
| `limits` | Per-event observed `{min,max}` ranges for `max_dossiers`, `max_source_excerpts`, `max_evidence_rows`. Configured limits are **never summed** across retries or counted as work. |
| `unavailable_token_measurements` | Number of explicit-null `input_tokens`, `output_tokens`, `cache_tokens` measurements, not missing turns. Separately, `counters.usage_unavailable_count`, when emitted by a producer, counts turns with unavailable usage. Omitted fields are not invented as zero or counted as explicit nulls. |
| `duration_ms` | `count`, `p50`, `p95`, `max`, `summed_work`; summaries are null when no duration was emitted. |

Invalid/nonfinite/negative/oversized measurements and invalid capability/outcome mappings increment
`measurement_gap_count`; at most 200 named `measurement_gaps` are retained.
`COUNTERS`, `OUTCOMES`, `OUTCOME_FIELDS`, `LIMITS`, `CAPABILITIES`, `CAPABILITY_COUNTERS`, `FLAGS`
and `DIMENSIONS` are closed in the source module. Aggregator support for a field does not prove a
producer emitted it; in particular pending final producer instrumentation is not supplied by
synthetic metrics fixtures. Aggregate counters
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
