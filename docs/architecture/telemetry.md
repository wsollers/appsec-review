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

## Interchange instrumentation

The [interchange upgrade](job-interchange.md) adds `HANDOFF_VALIDATED` and `HANDOFF_REJECTED`
alongside `HANDOFF_ACCEPTED`. The integration contract binds `handoff_reference`
(`path`, `sha256`, `size_bytes`), `duration_ms`, `execution_status`, `admission_status`,
`coverage_disposition`, `unit_count`, `gap_count`, and `retry_required`.
A rejection may use a null handoff reference only when a safe diagnostic publication is unavailable.
Accepted events retain `handoff_path`, `handoff_sha256`, and `completion_status` for existing
consumers. Validation events describe publication work, not repeated validation on checkpoint reuse.

`NATIVE_OUTPUT_RETAINED.retention_receipt` and
`OBSERVATION_PROVENANCE_VALIDATED.provenance_receipt` bind immutable retention/provenance
receipts; handoff events use `handoff_reference`. They describe retained bytes and resolving
observation references, not scanner-origin
attestation or vulnerability confirmation. Emit bounded identities, durations, counts, and hashes,
never raw reports, source, argv, secrets, or per-result message text. The fixed work-counter names
are `handoff_validations`, `native_output_references`, `native_output_bytes`,
`observation_references`, and `provenance_gaps`; paths, rule IDs, gap reasons, and arbitrary producer
status strings must not become unbounded counter labels.

The integrating metrics contract is `appsec-review/run-metrics/5`, adding `interchange` with schema
`appsec-review/interchange-metrics/1`. It derives publication/receipt identities and verifies the
referenced bytes and retention/provenance computation instead of trusting event-supplied counts.
Missing or tampered receipts are named integrity gaps, not zero work. Repeated publication/receipt
events deduplicate by identity, while reused evidence is not counted as fresh scanner work.
The closed groups are `handoffs`, `native_outputs`, `observations`, registered-job-only `by_job`,
and `integrity_gap_codes`. Section `accounting_complete` distinguishes measured accounting from
missing evidence; invalid/missing receipts yield null counts, not invented zeros. Rollups retain
coverage/execution/gap-code dimensions but never rule/path/hash/package/message labels.
Observation rollups also distinguish `provenance_complete_count` from
`provenance_incomplete_count` using receipt completeness, and `provenance_gap_count` sums common
observation `gap_ids` from the receipt computation. Root `duplicate_events` reports repeated
event identities without inflating the verified publication or receipt totals.
The receipt is authoritative, not the presence of a summary field. This section records the
integration contract, not evidence
that a deployed runtime has already adopted it.

## Existing derived views

`appsec-review metrics --run-id <id>` deterministically rebuilds and persists
`data/telemetry/summary.json` using `appsec-review/run-metrics/5` after interchange integration
(historical summaries use `/4`). It separates end-to-end wall time, per-job wall spans, summed
concurrent task time, queue delay, completed and still-running work, reuse, processed counts/bytes,
critical-path candidates, and bounded p50/p95/max rankings by stable operation identity. The JSONL
events remain authoritative; the summary is a regenerable operator view.

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
